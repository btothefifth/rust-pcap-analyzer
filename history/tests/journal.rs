use pcap_evidence_history::{analyze_file, recover_file, verify_file, Cancellation, Config};
use pcap_evidence_history::{
    journal::{self, Reader, Writer},
    query::History,
};
use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        let p = std::env::temp_dir().join(format!(
            "pcap-history-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&p).unwrap();
        Self(p)
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn fixture(temp: &Temp, name: &str, bytes: &[u8]) -> PathBuf {
    let p = temp.0.join(name);
    fs::write(&p, bytes).unwrap();
    p
}
#[test]
fn streaming_journal_reassembles_reordering_and_duplicates() {
    let t = Temp::new();
    let source = fixture(&t, "a.pcap", include_bytes!("../fixtures/reorder.pcap"));
    let dir = t.0.join("journal");
    let c = Config {
        sort_entries: 2,
        merge_fan_in: 2,
        ..Config::default()
    };
    let summary = analyze_file(&source, &dir, c, &Cancellation::default()).unwrap();
    assert_eq!(summary.packets, 4);
    assert_eq!(summary.intervals, 3);
    let mut h = History::open(&source, &dir).unwrap();
    let id = h.generations(None, 10).unwrap()[0];
    let result = h.range(id, 0, 0, 6).unwrap().encode();
    assert!(result.contains("616263"));
    assert!(result.contains("646566"));
    assert!(!result.contains("conflicting_bytes"));
    assert!(result.contains("policy_assumption"));
    assert!(result.contains("tcp_header_bytes"));
}
#[test]
fn late_conflicts_are_not_last_writer_wins() {
    let t = Temp::new();
    let source = fixture(
        &t,
        "a.pcap",
        include_bytes!("../fixtures/late-conflict.pcap"),
    );
    let dir = t.0.join("journal");
    analyze_file(&source, &dir, Config::default(), &Cancellation::default()).unwrap();
    let mut h = History::open(&source, &dir).unwrap();
    let id = h.generations(None, 10).unwrap()[0];
    assert!(h
        .range(id, 0, 0, 3)
        .unwrap()
        .encode()
        .contains("conflicting_bytes"));
}
#[test]
fn eviction_and_external_sort_are_replay_deterministic() {
    let t = Temp::new();
    let source = fixture(&t, "a.pcap", include_bytes!("../fixtures/interleaved.pcap"));
    let dir = t.0.join("journal");
    let c = Config {
        hot_tuples: 1,
        sort_entries: 2,
        merge_fan_in: 2,
        checkpoint_records: 2,
        ..Config::default()
    };
    analyze_file(&source, &dir, c, &Cancellation::default()).unwrap();
    verify_file(&source, &dir, &t.0.join("replay"), &Cancellation::default()).unwrap();
}
#[test]
fn changed_source_is_not_accepted() {
    let t = Temp::new();
    let source = fixture(&t, "a.pcap", include_bytes!("../fixtures/reorder.pcap"));
    let dir = t.0.join("journal");
    analyze_file(&source, &dir, Config::default(), &Cancellation::default()).unwrap();
    fs::write(&source, b"changed").unwrap();
    assert!(History::open(&source, &dir).is_err());
}
#[test]
fn partial_tail_requires_explicit_recovery() {
    let t = Temp::new();
    let source = fixture(&t, "a.pcap", include_bytes!("../fixtures/reorder.pcap"));
    let dir = t.0.join("journal");
    analyze_file(&source, &dir, Config::default(), &Cancellation::default()).unwrap();
    let file = dir.join("journal.bin");
    let mut bytes = fs::read(&file).unwrap();
    bytes.pop();
    fs::write(file, bytes).unwrap();
    assert!(History::open(&source, &dir).is_err());
    assert!(recover_file(
        &source,
        &dir,
        &t.0.join("denied"),
        false,
        &Cancellation::default()
    )
    .is_err());
    recover_file(
        &source,
        &dir,
        &t.0.join("recovered"),
        true,
        &Cancellation::default(),
    )
    .unwrap();
}
#[test]
fn corruption_is_not_torn_tail_recovery() {
    let t = Temp::new();
    let source = fixture(&t, "a.pcap", include_bytes!("../fixtures/reorder.pcap"));
    let dir = t.0.join("journal");
    analyze_file(&source, &dir, Config::default(), &Cancellation::default()).unwrap();
    let path = dir.join("journal.bin");
    let mut bytes = fs::read(&path).unwrap();
    let at = Reader::open(&path).unwrap().header.bytes as usize + 8;
    bytes[at] ^= 1;
    fs::write(path, bytes).unwrap();
    assert!(recover_file(
        &source,
        &dir,
        &t.0.join("bad"),
        true,
        &Cancellation::default()
    )
    .is_err());
}
#[test]
fn output_quota_does_not_create_a_complete_seal() {
    let t = Temp::new();
    let source = fixture(&t, "a.pcap", include_bytes!("../fixtures/interleaved.pcap"));
    let dir = t.0.join("journal");
    let c = Config {
        max_disk_bytes: 4096,
        ..Config::default()
    };
    assert!(analyze_file(&source, &dir, c, &Cancellation::default()).is_err());
    assert!(History::open(&source, &dir).is_err());
}
#[test]
fn cancellation_before_start_has_no_false_completion() {
    let t = Temp::new();
    let source = fixture(&t, "a.pcap", include_bytes!("../fixtures/reorder.pcap"));
    let cancel = Cancellation::default();
    cancel.cancel();
    let dir = t.0.join("journal");
    assert!(analyze_file(&source, &dir, Config::default(), &cancel).is_err());
    assert!(!dir.exists());
}
#[test]
fn duplicate_destination_is_no_clobber() {
    let t = Temp::new();
    let source = fixture(&t, "a.pcap", include_bytes!("../fixtures/reorder.pcap"));
    let dir = t.0.join("journal");
    analyze_file(&source, &dir, Config::default(), &Cancellation::default()).unwrap();
    let before = fs::read(dir.join("journal.bin")).unwrap();
    assert!(analyze_file(&source, &dir, Config::default(), &Cancellation::default()).is_err());
    assert_eq!(before, fs::read(dir.join("journal.bin")).unwrap());
}
#[test]
fn failed_writer_stays_poisoned() {
    let t = Temp::new();
    let source = pcap_evidence_history::SourceIdentity {
        sha256: [1; 32],
        bytes: 10,
    };
    let q = journal::quota(1024);
    let mut w = Writer::create(&t.0.join("j"), source, Config::default(), q).unwrap();
    assert!(w.append(journal::NOTICE, &vec![1; 1024]).is_err());
    assert!(w.append(journal::SEAL, &[]).is_err());
}
