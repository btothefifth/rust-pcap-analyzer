//! Small independent properties shared by the integration tests and native campaign.
//! No external corpus, coverage instrumentation, endpoint authority, or fuzz claim.
use pcap_evidence::{
    json::Json,
    provenance::{EvidenceBytes, PacketId},
    sha256,
};
use pcap_evidence_product::deep::{
    bgp::PcapMetadata,
    bgp_pipeline::CapturedSessionPipeline,
    bgp_policy::{self, BestPathInputs, PolicyCandidate, PolicyConfig, StepResult},
    bgp_rib::{
        AdjRibIn, ApplyStatus, PathId, RibAction, RibEvent, RibEventKind, RibScope, RouteStatus,
    },
    bgp_session::{Family, PartitionKind, SourcePartition},
    bgp_state::PrefixIdentity,
    bgp_store::{self, JournalWriter},
    Limits,
};
use std::{
    fs,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

pub const DISK_CAP: u64 = 64 * 1024;
pub const DEFAULT_SEED: u64 = 0x4271_7606_6793;

pub fn limits(input_bytes: usize, retained_bytes: usize) -> Limits {
    Limits {
        input_bytes,
        retained_bytes,
        output_bytes: retained_bytes,
        work: 2 * 1024 * 1024,
        elements: 128,
        active: 4,
        ..Limits::default()
    }
}
fn capture() -> [u8; 32] {
    sha256::digest(b"bounded-profile-capture")
}
fn metadata(frame: u64, direction: u8) -> PcapMetadata {
    PcapMetadata {
        source_id: "profile".into(),
        record_id: format!("message-{frame}"),
        observed_at_ns: Some(1000 - frame as i64),
        session: Some(17),
        direction: Some(direction),
        peer: Some(format!("peer-{direction}")),
        local: Some("local".into()),
    }
}
fn evidence(bytes: &[u8], frame: u64) -> EvidenceBytes {
    EvidenceBytes::from_packet(
        bytes,
        PacketId {
            capture: capture(),
            frame,
            record_offset: frame * 100,
        },
        54,
    )
}
fn message(kind: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![255; 16];
    out.extend_from_slice(&(19u16 + u16::try_from(body.len()).unwrap()).to_be_bytes());
    out.push(kind);
    out.extend_from_slice(body);
    out
}
fn open(asn: u16) -> Vec<u8> {
    // RFC 4271 section 4.2 plus RFC 6793 capability 65: independent byte arithmetic.
    let mut body = vec![4];
    body.extend_from_slice(&asn.to_be_bytes());
    body.extend_from_slice(&[0, 90, 192, 0, 2, 1, 8, 2, 6, 65, 4]);
    body.extend_from_slice(&u32::from(asn).to_be_bytes());
    message(1, &body)
}
fn update(octet: u8) -> Vec<u8> {
    // ORIGIN IGP; AS_SEQUENCE [65000] in negotiated four-octet grammar; NEXT_HOP.
    message(
        2,
        &[
            0, 0, 0, 20, 0x40, 1, 1, 0, 0x40, 2, 6, 2, 1, 0, 0, 0xfd, 0xe8, 0x40, 3, 4, 192, 0, 2,
            9, 24, 203, octet, 113,
        ],
    )
}
fn establish(p: &mut CapturedSessionPipeline) {
    for (frame, direction, asn) in [(1, 0, 65000), (2, 1, 65001)] {
        p.apply_message(&evidence(&open(asn), frame), metadata(frame, direction))
            .unwrap();
    }
}
fn snapshot(p: &CapturedSessionPipeline) -> String {
    format!(
        "{:?}{:?}{:?}{}{}",
        p.observer().view().unwrap(),
        p.rib().events(),
        p.rib().entries(),
        p.wire_state().generation(),
        p.tainted()
    )
}

/// Every truncation retains the complete declared length and reaches the wire
/// boundary with matching provenance/scope. A valid route is already present.
pub fn wire_property(value: u64, input: usize, retained: usize) -> usize {
    let mut p =
        CapturedSessionPipeline::new(capture(), "profile".into(), 17, limits(input, retained))
            .unwrap();
    establish(&mut p);
    let raw = update(value as u8);
    let accepted = p.apply_message(&evidence(&raw, 3), metadata(3, 0)).unwrap();
    assert!(!accepted.replayed);
    assert_eq!(
        p.rib()
            .entries()
            .values()
            .filter(|e| e.status == RouteStatus::Active)
            .count(),
        1
    );
    let before = snapshot(&p);
    for end in 1..raw.len() {
        assert!(
            p.apply_message(&evidence(&raw[..end], 4), metadata(4, 0))
                .is_err(),
            "truncation {end}"
        );
        assert_eq!(snapshot(&p), before, "truncation atomicity {end}");
    }
    let mut wrong = metadata(4, 0);
    wrong.source_id = "other".into();
    let error = p.apply_message(&evidence(&raw, 4), wrong).unwrap_err();
    assert_eq!(error.field, "bgp_pipeline_scope");
    let foreign = EvidenceBytes::from_packet(
        &raw,
        PacketId {
            capture: sha256::digest(b"other"),
            frame: 4,
            record_offset: 400,
        },
        54,
    );
    let error = p.apply_message(&foreign, metadata(4, 0)).unwrap_err();
    assert_eq!(error.field, "bgp_pipeline_capture");
    assert_eq!(snapshot(&p), before);
    // The survivor accepts a genuinely new valid record after every rejection.
    p.apply_message(&evidence(&raw, 5), metadata(5, 0)).unwrap();
    raw.len() - 1 + 2
}
fn prefix(value: u64) -> PrefixIdentity {
    PrefixIdentity {
        afi: 1,
        safi: 1,
        length: 24,
        address: format!("203.{}.113.0", value as u8),
    }
}
fn scope(source: &str, generation: u64) -> RibScope {
    RibScope {
        source: SourcePartition {
            kind: PartitionKind::Captured,
            source_id: source.into(),
            partition_id: format!("capture-{source}"),
        },
        session: "17".into(),
        generation,
        direction: Some(0),
        peer: Some("peer".into()),
    }
}
fn announce(source: &str, generation: u64, id: &str, path: u32, value: u64) -> RibEvent {
    RibEvent {
        scope: scope(source, generation),
        record_id: id.into(),
        kind: RibEventKind::Update(vec![RibAction::Announce {
            prefix: prefix(value),
            path_id: PathId::Present(path),
            attributes: Json::object([("origin", 0u32.into())]),
            attribute_identity: "origin-0".into(),
        }]),
    }
}
pub fn rib_property(value: u64, input: usize, retained: usize) {
    let mut rib = AdjRibIn::new(limits(input, retained)).unwrap();
    let original = announce("a", 0, "first", value as u32, value);
    rib.apply(original.clone()).unwrap();
    rib.apply(announce("b", 0, "sibling", value as u32, value))
        .unwrap();
    rib.apply(announce(
        "a",
        0,
        "path-sibling",
        (value as u32).wrapping_add(1),
        value,
    ))
    .unwrap();
    let mut withdrawn = original.clone();
    withdrawn.record_id = "withdraw".into();
    withdrawn.kind = RibEventKind::Update(vec![RibAction::Withdraw {
        prefix: prefix(value),
        path_id: PathId::Present(value as u32),
    }]);
    rib.apply(withdrawn).unwrap();
    assert_eq!(
        rib.entries()
            .values()
            .filter(|e| e.status == RouteStatus::Active)
            .count(),
        2
    );
    let mut reset_scope = scope("a", 1);
    reset_scope.direction = None;
    rib.apply(RibEvent {
        scope: reset_scope,
        record_id: "reset".into(),
        kind: RibEventKind::Reset {
            previous_generation: 0,
            reason: "transport".into(),
        },
    })
    .unwrap();
    assert_eq!(rib.apply(original).unwrap(), ApplyStatus::IdenticalReplay);
    assert_eq!(
        rib.apply(announce("a", 0, "late-old", value as u32, value))
            .unwrap(),
        ApplyStatus::Historical
    );
    let active: Vec<_> = rib
        .entries()
        .values()
        .filter(|e| e.status == RouteStatus::Active)
        .collect();
    assert_eq!(active.len(), 1);
    assert_eq!(active[0].key.scope.source.source_id, "b");
    rib.apply(announce("a", 1, "new", value as u32, value))
        .unwrap();
    assert_eq!(
        rib.entries()
            .values()
            .filter(|e| e.status == RouteStatus::Active)
            .count(),
        2
    );
    // Exact resource cut: fail after validation without publishing an event.
    let baseline = rib.clone();
    let mut tiny = AdjRibIn::new(limits(input, 1)).unwrap();
    assert!(tiny.apply(announce("a", 0, "budget", 1, value)).is_err());
    assert!(tiny.entries().is_empty() && tiny.events().is_empty());
    assert_eq!(rib.entries(), baseline.entries());
}
pub fn policy_property(value: u64, input: usize, retained: usize) -> bgp_policy::PolicyResult {
    let key = pcap_evidence_product::deep::bgp_rib::RouteKey {
        scope: scope("a", 0),
        family: Family { afi: 1, safi: 1 },
        path_id: PathId::Absent,
        prefix: prefix(value),
    };
    let low = (value % 1000) as u32;
    let candidate = |id: &str, lp| PolicyCandidate {
        id: id.into(),
        key: key.clone(),
        comparison_context: "router".into(),
        status: RouteStatus::Active,
        inputs: BestPathInputs {
            local_preference: lp,
            ..BestPathInputs::default()
        },
    };
    let config = PolicyConfig {
        provenance: "explicit-test-profile".into(),
        comparison_context: "router".into(),
        missing_local_preference: None,
        med_rule: None,
        age_rule: None,
    };
    let a = candidate("a", Some(low + 1));
    let b = candidate("b", Some(low));
    let l = limits(input, retained);
    let first = bgp_policy::evaluate(&config, &[a.clone(), b.clone()], &l).unwrap();
    assert_eq!(first.selected.as_deref(), Some("a"));
    let steps = &first.comparisons[0].steps;
    assert_eq!(steps.len(), 10); // Complete configured comparison trace, including skipped steps.
    assert_eq!(steps[0].criterion, "local_preference");
    assert_eq!(steps[0].result, StepResult::Left);
    assert!(steps[1..]
        .iter()
        .all(|step| step.result == StepResult::Skipped));
    assert_eq!(
        first,
        bgp_policy::evaluate(&config, &[b, a.clone()], &l).unwrap()
    );
    assert_no_authority(&first);
    let unknown = bgp_policy::evaluate(&config, &[a, candidate("b", None)], &l).unwrap();
    assert!(unknown.selected.is_none() && !unknown.unresolved.is_empty());
    // Canonical writer is atomic at exactly one byte below its real encoding.
    let encoded = first.encode_canonical(&l).unwrap();
    let mut exact = l.clone();
    exact.output_bytes = encoded.len();
    assert_eq!(first.encode_canonical(&exact).unwrap(), encoded);
    exact.output_bytes -= 1;
    let mut destination = b"survivor".to_vec();
    assert!(first.write_canonical(&mut destination, &exact).is_err());
    assert_eq!(destination, b"survivor");
    first
}
pub fn assert_no_authority(result: &bgp_policy::PolicyResult) {
    assert!(
        !result.endpoint_rib_established && !result.propagated_route_established,
        "offline policy invented endpoint authority"
    );
}

/// Scratch has one exact owner; only files created by this object are removed.
pub struct Scratch(PathBuf);
impl Scratch {
    pub fn create(parent: &Path, seed: u64) -> Self {
        let path = parent.join(format!("bgp-profile-{}-{seed}", std::process::id()));
        fs::create_dir(&path).expect("unique campaign scratch must not exist");
        Self(path)
    }
    pub fn path(&self) -> &Path {
        &self.0
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        for file in ["source.journal", "tampered.journal"] {
            let _ = fs::remove_file(self.0.join(file));
        }
        let _ = fs::remove_dir(&self.0);
    }
}
pub fn store_property(root: &Path, value: u64, input: usize, retained: usize) -> u64 {
    let path = root.join("source.journal");
    let tampered = root.join("tampered.journal");
    let l = limits(input, retained);
    let mut writer =
        JournalWriter::create(&path, "profile".into(), capture(), DISK_CAP, l.clone()).unwrap();
    let mut direct =
        CapturedSessionPipeline::new(capture(), "profile".into(), 17, l.clone()).unwrap();
    for (frame, direction, raw) in [
        (1, 0, open(65000)),
        (2, 1, open(65001)),
        (3, 0, update(value as u8)),
    ] {
        writer
            .message(17, &evidence(&raw, frame), &metadata(frame, direction))
            .unwrap();
        direct
            .apply_message(&evidence(&raw, frame), metadata(frame, direction))
            .unwrap();
    }
    let receipt = writer.seal().unwrap();
    let bytes = fs::read(&path).unwrap();
    assert!((bytes.len() as u64) * 2 < DISK_CAP);
    let fresh = bgp_store::replay(&path, DISK_CAP, l.clone()).unwrap();
    assert_eq!(fresh.receipt, receipt);
    assert_eq!(fresh.rejected_records, 0);
    assert_eq!(
        fresh.route_entries,
        direct.rib().entries().values().cloned().collect::<Vec<_>>()
    );
    assert!(fresh
        .json()
        .encode()
        .contains("\"endpoint_state_claimed\":false"));
    assert!(
        JournalWriter::create(&path, "profile".into(), capture(), DISK_CAP, l.clone()).is_err()
    );
    assert_eq!(fs::read(&path).unwrap(), bytes);
    // Same valid source and framing; flip a first-record digest byte, not magic.
    let first_record = 46 + "profile".len();
    let mut changed = bytes.clone();
    changed[first_record + 41] ^= 1;
    fs::write(&tampered, &changed).unwrap();
    let error = bgp_store::replay(&tampered, DISK_CAP, l.clone()).unwrap_err();
    assert_eq!(error.field, "bgp_journal_digest");
    assert_eq!(
        bgp_store::replay(&path, DISK_CAP, l).unwrap().receipt,
        receipt
    );
    fs::remove_file(path).unwrap();
    fs::remove_file(tampered).unwrap();
    (bytes.len() as u64) * 2
}

#[derive(Debug)]
pub struct Receipt {
    pub iterations: u64,
    pub negative_wire_cases: usize,
    pub disk_peak: u64,
    pub elapsed_ms: u128,
}
pub fn run(
    seed: u64,
    iterations: u64,
    input: usize,
    retained: usize,
    seconds: u64,
    parent: &Path,
) -> Receipt {
    assert!((1..=10_000).contains(&iterations));
    assert!((32 * 1024..=64 * 1024).contains(&input));
    assert!((128 * 1024..=4 * 1024 * 1024).contains(&retained));
    assert!((1..=60).contains(&seconds));
    let start = Instant::now();
    let budget = Duration::from_secs(seconds);
    let scratch = Scratch::create(parent, seed);
    let mut rng = seed;
    let mut count = 0;
    let mut negatives = 0;
    let mut disk_peak = 0;
    while count < iterations && start.elapsed() < budget {
        rng = rng
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        negatives += wire_property(rng, input, retained);
        rib_property(rng, input, retained);
        policy_property(rng, input, retained);
        disk_peak = disk_peak.max(store_property(scratch.path(), rng, input, retained));
        count += 1;
    }
    Receipt {
        iterations: count,
        negative_wire_cases: negatives,
        disk_peak,
        elapsed_ms: start.elapsed().as_millis(),
    }
}
