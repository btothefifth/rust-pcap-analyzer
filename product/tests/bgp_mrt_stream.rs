//! Tiny and virtual sources; no corpus, persistent large fixture, or packet IDs.
use pcap_evidence::{json::Json, sha256};
use pcap_evidence_product::deep::{
    bgp_mrt::{MrtBatch, MrtLimits, MrtSource},
    bgp_mrt_store::MrtReplayOptions,
    bgp_mrt_stream::{visit_verified, StreamEvent},
    bgp_mrt_stream_store::{verify_stream, write_stream, MrtStreamLimits},
    Limits,
};
use std::io::{self, Cursor, Read, Seek, SeekFrom, Write};
fn source() -> MrtSource {
    MrtSource {
        source_id: "collector-a".into(),
        checkpoint_id: "checkpoint-a".into(),
    }
}
fn record(t: u32, kind: u16, subtype: u16, b: &[u8]) -> Vec<u8> {
    let mut v = t.to_be_bytes().to_vec();
    v.extend(kind.to_be_bytes());
    v.extend(subtype.to_be_bytes());
    v.extend((b.len() as u32).to_be_bytes());
    v.extend(b);
    v
}
fn store(raw: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    write_stream(
        &mut Cursor::new(raw),
        &mut out,
        raw.len() as u64,
        source(),
        &MrtStreamLimits::default(),
    )
    .unwrap();
    out
}
fn visit(
    raw: &[u8],
    mut f: impl FnMut(StreamEvent<'_>) -> pcap_evidence::Result<()>,
) -> pcap_evidence::Result<pcap_evidence_product::deep::bgp_mrt_stream_store::StreamReceipt> {
    visit_verified(
        &mut Cursor::new(store(raw)),
        &MrtStreamLimits::default(),
        &Limits::default(),
        &MrtReplayOptions::default(),
        &mut f,
    )
}
fn member<'a>(j: &'a Json, key: &str) -> Option<&'a Json> {
    if let Json::Object(items) = j {
        items.iter().find_map(|(k, v)| (*k == key).then_some(v))
    } else {
        None
    }
}
fn table() -> Vec<u8> {
    let mut b = vec![
        192, 0, 2, 1, 0, 1, b'v', 0, 1, 2, 192, 0, 2, 2, 203, 0, 113, 9,
    ];
    b.extend(65551u32.to_be_bytes());
    record(11, 13, 1, &b)
}
fn rib() -> Vec<u8> {
    let mut attrs = vec![0x40, 1, 1, 0, 0x40, 2, 6, 2, 1];
    attrs.extend(65551u32.to_be_bytes());
    attrs.extend([0x40, 3, 4, 192, 0, 2, 9]);
    let mut b = vec![0, 0, 0, 7, 8, 10, 0, 1, 0, 0];
    b.extend(10u32.to_be_bytes());
    b.extend((attrs.len() as u16).to_be_bytes());
    b.extend(attrs);
    record(12, 13, 2, &b)
}

struct Split<'a> {
    bytes: &'a [u8],
    at: usize,
    width: usize,
}
impl Read for Split<'_> {
    fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
        let n = b.len().min(self.width).min(self.bytes.len() - self.at);
        b[..n].copy_from_slice(&self.bytes[self.at..self.at + n]);
        self.at += n;
        Ok(n)
    }
}
#[test]
fn arbitrary_read_splits_preserve_exact_source_and_record_identity() {
    let raw = [record(7, 99, 0, b"opaque"), record(8, 99, 1, b"more")].concat();
    let expected = store(&raw);
    for width in 1..=raw.len() {
        let mut out = Vec::new();
        let receipt = write_stream(
            &mut Split {
                bytes: &raw,
                at: 0,
                width,
            },
            &mut out,
            raw.len() as u64,
            source(),
            &MrtStreamLimits::default(),
        )
        .unwrap();
        assert_eq!(out, expected);
        assert_eq!(receipt.sha256, sha256::hex(&sha256::digest(&raw)));
    }
    let mut rows = Vec::new();
    let receipt = visit(&raw, |e| {
        rows.push((
            e.record_ordinal,
            e.record_offset,
            e.record_bytes,
            e.record_sha256.to_owned(),
            e.receipt.sha256.clone(),
        ));
        Ok(())
    })
    .unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].0, 0);
    assert_eq!(rows[1].1, 18);
    assert_eq!(rows[0].3, sha256::hex(&sha256::digest(&raw[..18])));
    assert!(rows.iter().all(|r| r.4 == receipt.sha256));
}
#[test]
fn every_store_truncation_corruption_and_trailing_byte_precedes_callbacks() {
    let encoded = store(&record(1, 99, 0, b"opaque"));
    for end in 0..encoded.len() {
        let mut called = 0;
        assert!(visit_verified(
            &mut Cursor::new(&encoded[..end]),
            &MrtStreamLimits::default(),
            &Limits::default(),
            &MrtReplayOptions::default(),
            |_| {
                called += 1;
                Ok(())
            }
        )
        .is_err());
        assert_eq!(called, 0);
    }
    let header = 20 + source().source_id.len() + source().checkpoint_id.len();
    // Header source label, frame ordinal, offset, length, record digest, chain,
    // raw body, terminal digest, and seal are independent corruption surfaces.
    for at in [
        20,
        header + 1,
        header + 9,
        header + 17,
        header + 21,
        header + 53,
        header + 85 + 12,
        encoded.len() - 65,
        encoded.len() - 1,
    ] {
        let mut bytes = encoded.clone();
        bytes[at] ^= 1;
        let mut called = 0;
        assert!(
            visit_verified(
                &mut Cursor::new(bytes),
                &MrtStreamLimits::default(),
                &Limits::default(),
                &MrtReplayOptions::default(),
                |_| {
                    called += 1;
                    Ok(())
                }
            )
            .is_err(),
            "corruption at {at}"
        );
        assert_eq!(called, 0);
    }
    let mut bytes = encoded;
    bytes.push(0);
    assert!(verify_stream(&mut Cursor::new(bytes), &MrtStreamLimits::default()).is_err());
}
#[test]
fn exact_resource_caps_accept_and_one_below_rejects() {
    let raw = record(1, 99, 0, b"opaque");
    let encoded = store(&raw);
    let mut l = MrtStreamLimits {
        source_bytes: raw.len() as u64,
        store_bytes: encoded.len() as u64,
        records: 1,
        record_bytes: raw.len(),
        ..MrtStreamLimits::default()
    };
    let receipt = write_stream(
        &mut Cursor::new(&raw),
        &mut Vec::new(),
        raw.len() as u64,
        source(),
        &l,
    )
    .unwrap();
    l.work = receipt.work_used;
    write_stream(
        &mut Cursor::new(&raw),
        &mut Vec::new(),
        raw.len() as u64,
        source(),
        &l,
    )
    .unwrap();
    for field in 0..4 {
        let mut less = l.clone();
        match field {
            0 => less.source_bytes -= 1,
            1 => less.store_bytes -= 1,
            2 => less.record_bytes -= 1,
            _ => less.work -= 1,
        };
        assert!(write_stream(
            &mut Cursor::new(&raw),
            &mut Vec::new(),
            raw.len() as u64,
            source(),
            &less
        )
        .is_err());
    }
    let twice = [raw.clone(), raw].concat();
    assert!(write_stream(
        &mut Cursor::new(&twice),
        &mut Vec::new(),
        twice.len() as u64,
        source(),
        &MrtStreamLimits {
            records: 1,
            ..MrtStreamLimits::default()
        }
    )
    .is_err());
    let all = visit_verified(
        &mut Cursor::new(&encoded),
        &MrtStreamLimits::default(),
        &Limits::default(),
        &MrtReplayOptions::default(),
        |_| Ok(()),
    )
    .unwrap();
    for (work, output) in [
        (all.work_used, all.output_bytes),
        (all.work_used - 1, all.output_bytes),
        (all.work_used, all.output_bytes - 1),
    ] {
        let result = visit_verified(
            &mut Cursor::new(&encoded),
            &MrtStreamLimits {
                work,
                output_bytes: output,
                ..MrtStreamLimits::default()
            },
            &Limits::default(),
            &MrtReplayOptions::default(),
            |_| Ok(()),
        );
        assert_eq!(
            result.is_ok(),
            work == all.work_used && output == all.output_bytes
        );
    }
}
#[test]
fn retained_representation_cap_accepts_exact_and_rejects_one_below_before_callback() {
    let encoded = store(&record(1, 99, 0, b"opaque"));
    let full = visit_verified(
        &mut Cursor::new(&encoded),
        &MrtStreamLimits::default(),
        &Limits::default(),
        &MrtReplayOptions::default(),
        |_| Ok(()),
    )
    .unwrap();
    for retained in [full.high_water_bytes, full.high_water_bytes - 1] {
        let mut called = 0;
        let result = visit_verified(
            &mut Cursor::new(&encoded),
            &MrtStreamLimits::default(),
            &Limits {
                retained_bytes: retained,
                ..Limits::default()
            },
            &MrtReplayOptions::default(),
            |_| {
                called += 1;
                Ok(())
            },
        );
        assert_eq!(result.is_ok(), retained == full.high_water_bytes);
        if result.is_err() {
            assert_eq!(called, 0);
        }
    }
}

#[test]
fn admitted_length_rejects_truncation_growth_and_partial_record_without_seal() {
    let raw = record(1, 99, 0, b"opaque");
    for length in [raw.len() - 1, raw.len() + 1] {
        let mut out = Vec::new();
        assert!(write_stream(
            &mut Cursor::new(&raw),
            &mut out,
            length as u64,
            source(),
            &MrtStreamLimits::default()
        )
        .is_err());
        assert!(verify_stream(&mut Cursor::new(out), &MrtStreamLimits::default()).is_err());
    }
    let mut extra = raw.clone();
    extra.push(0);
    assert!(write_stream(
        &mut Cursor::new(extra),
        &mut Vec::new(),
        raw.len() as u64,
        source(),
        &MrtStreamLimits::default()
    )
    .is_err());
}
#[test]
fn actual_pit_offsets_and_digests_survive_opaque_addpath_series() {
    let prefix = record(1, 99, 0, b"before");
    let pit = table();
    let mut raw = [prefix.clone(), pit.clone()].concat();
    for subtype in 8..=12 {
        raw.extend(record(11, 13, subtype, &[0, 0, 0, 1]));
    }
    raw.extend(rib());
    let batch = MrtBatch::parse(&raw, source(), &MrtLimits::default()).unwrap();
    let expected = batch
        .normalize_rib_entry(7, 0, &Limits::default())
        .unwrap()
        .unwrap();
    let mut got = None;
    visit(&raw, |e| {
        if e.entry_index == Some(0) {
            assert_eq!(e.record_ordinal, 7);
            assert_eq!(e.originated_seconds, Some(10));
            got = e.observation.cloned();
        }
        Ok(())
    })
    .unwrap();
    assert_eq!(got, Some(expected));
    let invalid = [pit.clone(), record(11, 99, 0, b"unrelated"), rib()].concat();
    assert!(write_stream(
        &mut Cursor::new(&invalid),
        &mut Vec::new(),
        invalid.len() as u64,
        source(),
        &MrtStreamLimits::default()
    )
    .is_err());
    let two = [pit.clone(), pit, rib()].concat();
    let limit = MrtStreamLimits {
        peers: 1,
        ..MrtStreamLimits::default()
    };
    write_stream(
        &mut Cursor::new(&two),
        &mut Vec::new(),
        two.len() as u64,
        source(),
        &limit,
    )
    .unwrap();
}
fn bgp(kind: u8, payload: &[u8]) -> Vec<u8> {
    let mut b = vec![255; 16];
    b.extend(((19 + payload.len()) as u16).to_be_bytes());
    b.push(kind);
    b.extend(payload);
    b
}
fn outer(subtype: u16, payload: &[u8], peer: u16) -> Vec<u8> {
    let mut b = peer.to_be_bytes().to_vec();
    b.extend(65002u16.to_be_bytes());
    b.extend([0, 1, 0, 1, 203, 0, 113, 1, 192, 0, 2, 1]);
    b.extend(payload);
    record(30, 16, subtype, &b)
}
fn state(old: u16, new: u16) -> Vec<u8> {
    outer(0, &[old.to_be_bytes(), new.to_be_bytes()].concat(), 65001)
}
fn open(asn: u16, id: u8) -> Vec<u8> {
    let mut b = vec![4];
    b.extend(asn.to_be_bytes());
    b.extend([0, 90, 192, 0, 2, id, 0]);
    bgp(1, &b)
}
fn update() -> Vec<u8> {
    let attrs = [
        0x40, 1, 1, 0, 0x40, 2, 4, 2, 1, 0xfd, 0xe9, 0x40, 3, 4, 192, 0, 2, 9,
    ];
    let mut b = vec![0, 0];
    b.extend((attrs.len() as u16).to_be_bytes());
    b.extend(attrs);
    b.extend([24, 198, 51, 100]);
    bgp(2, &b)
}
fn established() -> Vec<u8> {
    [
        state(1, 2),
        state(2, 4),
        outer(1, &open(65001, 1), 65001),
        outer(6, &open(65002, 2), 65001),
        state(4, 5),
        state(5, 6),
        outer(1, &update(), 65001),
    ]
    .concat()
}
#[test]
fn bgp4mp_open_fsm_and_update_grammar_continues_across_records() {
    let raw = established();
    let mut observations = Vec::new();
    visit(&raw, |e| {
        if let Some(j) = e.observation {
            observations.push(j.clone());
            assert_eq!(e.record_ordinal, 6);
        }
        Ok(())
    })
    .unwrap();
    assert_eq!(observations.len(), 1);
    let context =
        member(&observations[0], "import_context").or_else(|| member(&observations[0], "context"));
    // Canonical replay envelope carries whole-source identity and has no packet carrier.
    let encoded = observations[0].encode();
    assert!(encoded.contains(&sha256::hex(&sha256::digest(&raw))));
    assert!(!encoded.contains("packet_id"));
    let _ = context;
    let broken = [established(), state(6, 1), outer(1, &update(), 65001)].concat();
    let mut count = 0;
    visit(&broken, |e| {
        count += usize::from(e.observation.is_some());
        Ok(())
    })
    .unwrap();
    assert_eq!(count, 1);
    let two = [
        outer(0, &[0, 1, 0, 2], 65001),
        outer(0, &[0, 1, 0, 2], 65003),
    ]
    .concat();
    let bytes = store(&two);
    assert!(visit_verified(
        &mut Cursor::new(bytes),
        &MrtStreamLimits {
            sessions: 1,
            ..MrtStreamLimits::default()
        },
        &Limits::default(),
        &MrtReplayOptions::default(),
        |_| Ok(())
    )
    .is_err());
}
#[test]
fn invalid_et_update_keeps_unknown_observation_time_in_stream_and_v1_replay() {
    static SERIAL: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let ordinary = established();
    let last = outer(1, &update(), 65001);
    for micros in [999_999u32, 1_000_000u32] {
        let mut raw = ordinary[..ordinary.len() - last.len()].to_vec();
        let mut body = micros.to_be_bytes().to_vec();
        body.extend_from_slice(&last[12..]);
        raw.extend(record(30, 17, 1, &body));
        let mut normalized = None;
        visit(&raw, |e| {
            if let Some(observation) = e.observation {
                assert_eq!(e.record_type, 17);
                assert_eq!(e.time.microseconds, Some(micros));
                normalized = Some(observation.clone());
            }
            Ok(())
        })
        .unwrap();
        let normalized = normalized.expect("valid UPDATE survives unavailable numeric time");
        let expected = if micros < 1_000_000 {
            Json::from("30999999000")
        } else {
            Json::Null
        };
        assert_eq!(member(&normalized, "observed_at_ns"), Some(&expected));
        if micros >= 1_000_000 {
            assert!(normalized.encode().contains("invalid_mrt_record_timestamp"));
        }

        // The existing whole-source store reaches the same canonical owner.
        let directory = std::env::temp_dir().join(format!(
            "pcap-mrt-et-clock-{}-{}",
            std::process::id(),
            SERIAL.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        std::fs::create_dir(&directory).unwrap();
        let path = directory.join("source-v1.pcbmrt");
        let archive = pcap_evidence_product::deep::bgp_mrt_store::create(
            &path,
            &raw,
            source(),
            1024 * 1024,
            MrtLimits::default(),
            Limits::default(),
        )
        .unwrap();
        assert_eq!(archive.bgp4mp_candidates.len(), 1);
        let observation = archive
            .bgp4mp_candidate_observation(&archive.bgp4mp_candidates[0])
            .unwrap();
        // Json::Object equality includes insertion order. Both complete values
        // must traverse the real observation consumer before parity comparison;
        // its canonical object ordering retains all fields and array order.
        let stream_observation =
            pcap_evidence_product::deep::bgp_state::Observation::from_normalized(
                &normalized,
                None,
                &Limits::default(),
            )
            .unwrap();
        assert_eq!(observation.normalized(), stream_observation.normalized());
        assert_eq!(observation.sha256(), stream_observation.sha256());
        std::fs::remove_file(path).unwrap();
        std::fs::remove_dir(directory).unwrap();
    }
}

#[test]
fn exact_record_discriminator_preserves_malformed_and_invalid_et_time() {
    let raw = [
        record(30, 16, 99, &[]),
        record(31, 17, 1, &[1, 2, 3]),
        record(32, 17, 99, &1_000_000u32.to_be_bytes()),
        record(33, 17, 99, &999_999u32.to_be_bytes()),
    ]
    .concat();
    let mut times = Vec::new();
    visit(&raw, |e| {
        times.push((
            e.record_type,
            e.subtype,
            e.time.seconds,
            e.time.microseconds,
        ));
        assert!(e.observation.is_none());
        Ok(())
    })
    .unwrap();
    assert_eq!(
        times,
        vec![
            (16, 99, 30, None),
            (17, 1, 31, None),
            (17, 99, 32, Some(1_000_000)),
            (17, 99, 33, Some(999_999))
        ]
    );
}

struct ReplaceOnReplay {
    first: Cursor<Vec<u8>>,
    second: Vec<u8>,
    seeks: usize,
}
impl Read for ReplaceOnReplay {
    fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
        self.first.read(b)
    }
}
impl Seek for ReplaceOnReplay {
    fn seek(&mut self, p: SeekFrom) -> io::Result<u64> {
        if p == SeekFrom::Start(0) {
            self.seeks += 1;
            if self.seeks == 2 {
                self.first = Cursor::new(self.second.clone());
            }
        }
        self.first.seek(p)
    }
}
#[test]
fn second_pass_rebuilt_store_change_rejects_final_receipt() {
    let mut reader = ReplaceOnReplay {
        first: Cursor::new(store(&record(1, 99, 0, b"opaque"))),
        second: store(&record(2, 99, 0, b"opaque")),
        seeks: 0,
    };
    let mut called = 0;
    assert!(visit_verified(
        &mut reader,
        &MrtStreamLimits::default(),
        &Limits::default(),
        &MrtReplayOptions::default(),
        |_| {
            called += 1;
            Ok(())
        }
    )
    .is_err());
    assert_eq!(
        called, 1,
        "callback was provisional until final identity comparison"
    );
}

// Virtual >64 MiB witness: one repeated raw record, and a seekable writer that
// retains only each tiny metadata segment plus the 12-byte repeated header.
struct RepeatedSource {
    header: [u8; 12],
    record_bytes: u64,
    bytes: u64,
    at: u64,
}
impl Read for RepeatedSource {
    fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
        let n = b.len().min((self.bytes - self.at) as usize);
        b[..n].fill(0);
        for (i, v) in b[..n].iter_mut().enumerate() {
            let pos = (self.at + i as u64) % self.record_bytes;
            if pos < 12 {
                *v = self.header[pos as usize];
            }
        }
        self.at += n as u64;
        Ok(n)
    }
}
struct Segment {
    start: u64,
    len: u64,
    prefix: Vec<u8>,
}
#[derive(Default)]
struct VirtualStore {
    parts: Vec<Segment>,
    len: u64,
    at: u64,
}
impl Write for VirtualStore {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        self.parts.push(Segment {
            start: self.len,
            len: b.len() as u64,
            prefix: if b.len() > 1024 {
                b[..12].to_vec()
            } else {
                b.to_vec()
            },
        });
        self.len += b.len() as u64;
        Ok(b.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
impl Read for VirtualStore {
    fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
        if self.at == self.len {
            return Ok(0);
        }
        let s = self
            .parts
            .iter()
            .find(|s| self.at >= s.start && self.at < s.start + s.len)
            .unwrap();
        let offset = (self.at - s.start) as usize;
        let n = b.len().min((s.len as usize) - offset);
        b[..n].fill(0);
        if offset < s.prefix.len() {
            let c = n.min(s.prefix.len() - offset);
            b[..c].copy_from_slice(&s.prefix[offset..offset + c]);
        }
        self.at += n as u64;
        Ok(n)
    }
}
impl Seek for VirtualStore {
    fn seek(&mut self, p: SeekFrom) -> io::Result<u64> {
        let n = match p {
            SeekFrom::Start(n) => i128::from(n),
            SeekFrom::Current(n) => i128::from(self.at) + i128::from(n),
            SeekFrom::End(n) => i128::from(self.len) + i128::from(n),
        };
        if n < 0 || n > i128::from(self.len) {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        self.at = n as u64;
        Ok(self.at)
    }
}
#[test]
fn virtual_source_above_batch_ceiling_has_constant_record_high_water() {
    let n = 1024 * 1024u64;
    let mut header = [0u8; 12];
    header[4..6].copy_from_slice(&99u16.to_be_bytes());
    header[8..12].copy_from_slice(&((n - 12) as u32).to_be_bytes());
    let mut high = Vec::new();
    for count in [1, 65] {
        let length = n * count;
        let mut raw = RepeatedSource {
            header,
            record_bytes: n,
            bytes: length,
            at: 0,
        };
        let mut out = VirtualStore::default();
        let written = write_stream(
            &mut raw,
            &mut out,
            length,
            source(),
            &MrtStreamLimits::default(),
        )
        .unwrap();
        assert_eq!(written.record_count, count);
        assert!(out.parts.iter().map(|p| p.prefix.len()).sum::<usize>() < 32 * 1024);
        let mut rows = 0;
        let receipt = visit_verified(
            &mut out,
            &MrtStreamLimits::default(),
            &Limits::default(),
            &MrtReplayOptions::default(),
            |e| {
                assert!(e.observation.is_none());
                rows += 1;
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(rows, count);
        assert_eq!(receipt.sha256, written.sha256);
        high.push(receipt.high_water_bytes);
        if count == 65 {
            assert!(receipt.byte_length > 64 * 1024 * 1024);
        }
    }
    assert_eq!(high[0], high[1]);
    assert!(high[1] < 3 * 1024 * 1024);
}
