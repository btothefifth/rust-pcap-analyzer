use pcap_evidence::{sha256, wire::Endpoint};
use pcap_evidence_history::state::{epoch_candidates, TupleState};
use pcap_evidence_history::{Config, EpochPolicy, Key, SourceIdentity, TcpInput, Witness};
fn source() -> SourceIdentity {
    SourceIdentity {
        sha256: [7; 32],
        bytes: 1000000,
    }
}
fn key() -> Key {
    Key {
        section: 0,
        interface: 0,
        vlans: vec![8],
        tunnels: vec![],
        a: Endpoint {
            address: "192.0.2.1".parse().unwrap(),
            port: 12000,
        },
        b: Endpoint {
            address: "192.0.2.2".parse().unwrap(),
            port: 20000,
        },
    }
}
fn packet(frame: u64, seq: u32, flags: u8, payload: &[u8]) -> TcpInput {
    let mut raw = vec![0; 20];
    raw[0..2].copy_from_slice(&12000u16.to_be_bytes());
    raw[2..4].copy_from_slice(&20000u16.to_be_bytes());
    raw[4..8].copy_from_slice(&seq.to_be_bytes());
    raw[12] = 0x50;
    raw[13] = flags;
    raw[14..16].copy_from_slice(&4096u16.to_be_bytes());
    raw.extend_from_slice(payload);
    let w = Witness {
        start: 0,
        end: raw.len() as u32,
        frame,
        record_offset: 24,
        packet_start: 34,
        source_offset: 74,
    };
    TcpInput::new(
        key(),
        0,
        frame,
        Some(frame as i128),
        raw,
        vec![w],
        &Config::default(),
    )
    .unwrap()
}
#[test]
fn known_serial_aliases() {
    assert_eq!(
        epoch_candidates(0, 0, 0, 2 * (1i64 << 32), 4).unwrap(),
        vec![0, 1i64 << 32, 2 * (1i64 << 32)]
    );
    assert_eq!(epoch_candidates(u32::MAX, 0, -5, 0, 4).unwrap(), vec![-1]);
    assert!(epoch_candidates(0, 0, 0, 10 * (1i64 << 32), 4).is_err());
}
#[test]
fn syn_anchor_and_duplicate_have_identical_placement() {
    let c = Config::default();
    let mut s = TupleState::new(key());
    s.ingest(&packet(1, 100, 2, b""), &source(), &c).unwrap();
    let first = s
        .ingest(&packet(2, 101, 16, b"abc"), &source(), &c)
        .unwrap();
    let second = s
        .ingest(&packet(3, 101, 16, b"abc"), &source(), &c)
        .unwrap();
    assert_eq!(first.placements, second.placements);
    assert_eq!(first.placements[0].offset, 0);
    assert!(first.placements[0].selected);
}
#[test]
fn late_conflicting_bytes_keep_the_same_source_position() {
    let c = Config::default();
    let mut s = TupleState::new(key());
    s.ingest(&packet(1, 100, 2, b""), &source(), &c).unwrap();
    let a = s
        .ingest(&packet(2, 101, 16, b"abc"), &source(), &c)
        .unwrap();
    let b = s
        .ingest(&packet(3, 101, 16, b"aXc"), &source(), &c)
        .unwrap();
    assert_eq!(a.placements, b.placements);
    assert_ne!(
        packet(2, 101, 16, b"abc").payload(),
        packet(3, 101, 16, b"aXc").payload()
    );
}
#[test]
fn reset_and_tuple_reuse_keep_old_generation() {
    let c = Config::default();
    let mut s = TupleState::new(key());
    let a = s.ingest(&packet(1, 100, 2, b""), &source(), &c).unwrap();
    s.ingest(&packet(2, 101, 20, b"old"), &source(), &c)
        .unwrap();
    let b = s.ingest(&packet(3, 100, 2, b""), &source(), &c).unwrap();
    assert_ne!(a.placements[0].generation, b.placements[0].generation);
    let late = s
        .ingest(&packet(4, 101, 16, b"old"), &source(), &c)
        .unwrap();
    assert_eq!(late.placements.len(), 2);
    assert!(late.placements.iter().all(|p| !p.selected));
}
#[test]
fn missing_handshake_never_becomes_complete() {
    let mut s = TupleState::new(key());
    s.ingest(&packet(1, 100, 16, b"abc"), &source(), &Config::default())
        .unwrap();
    assert!(s.generations[0].midstream);
    assert!(s.generations[0].syn[0].is_none());
}
#[test]
fn clock_reversal_is_diagnostic_not_sequence_clock() {
    let c = Config::default();
    let mut s = TupleState::new(key());
    let mut a = packet(1, 100, 2, b"");
    a.when = Some(100);
    s.ingest(&a, &source(), &c).unwrap();
    let b = s
        .ingest(&packet(2, 101, 16, b"abc"), &source(), &c)
        .unwrap();
    assert!(b.reasons.iter().any(|s| s == "capture_clock_reversal"));
    assert_eq!(b.placements[0].offset, 0);
}
#[test]
fn more_than_two_wraps_require_an_explicit_epoch_assumption() {
    let c = Config {
        sequence_horizon: 1_100_000_000,
        epoch_policy: EpochPolicy::NearestFrontier,
        ..Config::default()
    };
    let mut s = TupleState::new(key());
    s.ingest(&packet(1, 100, 2, b""), &source(), &c).unwrap();
    let mut assumption_seen = false;
    for i in 0..11u64 {
        let relative = i * 1_000_000_000;
        let p = packet(i + 2, 101u32.wrapping_add(relative as u32), 16, b"x");
        let d = s.ingest(&p, &source(), &c).unwrap();
        let chosen = d.placements.iter().find(|p| p.selected).unwrap();
        assert_eq!(chosen.offset, relative as i64);
        assumption_seen |= d.policy_assumption;
    }
    assert!(assumption_seen);
    assert!(s.generations[0].high[0] > 2 * (1i64 << 32));
}
#[test]
fn strict_mode_does_not_discard_earlier_epoch() {
    let c = Config {
        sequence_horizon: 1_100_000_000,
        ..Config::default()
    };
    let mut s = TupleState::new(key());
    s.ingest(&packet(1, 100, 2, b""), &source(), &c).unwrap();
    for i in 0..4u64 {
        s.ingest(
            &packet(
                i + 2,
                101u32.wrapping_add((i * 1_000_000_000) as u32),
                16,
                b"x",
            ),
            &source(),
            &c,
        )
        .unwrap();
    }
    s.generations[0].high[0] = 5_000_000_000;
    let d = s.ingest(&packet(10, 101, 16, b"x"), &source(), &c).unwrap();
    assert!(d.placements.len() > 1);
    assert!(d.placements.iter().all(|p| !p.selected));
}
#[test]
fn cached_header_forgery_does_not_change_parsed_sequence() {
    let c = Config::default();
    let mut s = TupleState::new(key());
    s.ingest(&packet(1, 100, 2, b""), &source(), &c).unwrap();
    let mut p = packet(2, 101, 16, b"abc");
    p.sequence = 999999;
    p.header_bytes = 0;
    let d = s.ingest(&p, &source(), &c).unwrap();
    assert_eq!(d.placements[0].offset, 0);
}
#[test]
fn codec_round_trip_preserves_state() {
    let c = Config::default();
    let mut s = TupleState::new(key());
    s.ingest(&packet(1, 100, 2, b""), &source(), &c).unwrap();
    let b = s.encode().unwrap();
    assert_eq!(TupleState::decode(&b, &c).unwrap(), s);
    assert_eq!(sha256::digest(&b), sha256::digest(&s.encode().unwrap()));
}
#[test]
fn generation_quota_failure_does_not_mutate_state() {
    let c = Config {
        max_generations: 1,
        ..Config::default()
    };
    let mut s = TupleState::new(key());
    s.ingest(&packet(1, 100, 2, b""), &source(), &c).unwrap();
    let before = s.encode().unwrap();
    assert!(s.ingest(&packet(2, 200, 2, b""), &source(), &c).is_err());
    assert_eq!(s.encode().unwrap(), before);
}
#[test]
fn malformed_options_are_errors() {
    let mut p = packet(1, 100, 2, b"xxxx");
    p.raw[12] = 0x60;
    p.raw[20] = 8;
    p.raw[21] = 0;
    assert!(TcpInput::decode(&p.encode().unwrap(), &Config::default()).is_err());
}
