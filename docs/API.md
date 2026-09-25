# API and command-line guide

## Atomic captured BGP session pipeline

`deep::bgp_pipeline::CapturedSessionPipeline` binds one capture namespace, source
label, and TCP session, then applies each already-framed BGP message atomically
to the wire decoder, offline session observer, and Adj-RIB-In candidate model.
It exposes explicit EOR, protocol-reset, gap and transport-generation boundaries;
ambiguous attributes cannot become active candidates, and a changed immutable
record identity permanently taints the instance. See
[product/BGP_PIPELINE.md](product/BGP_PIPELINE.md). `pcap-depth analyze` now
persists `depth_bgp_pipeline` receipts on BGP message events and
`depth_bgp_session_summary` on flow-end events. A successful run also publishes
a sealed `bgp.journal`; `deep::bgp_store` verifies its hash chain and replays the
exact message bytes, packet spans, and boundaries through a new manager in a
fresh process. Stateful protocol messages from the
two reconstructed TCP directions are emitted by completion-evidence order while
each direction remains decoded in TCP sequence order.

`deep::bgp_mrt_store` provides the corresponding source-first persistence path
for external MRT. It seals exact MRT bytes plus source/checkpoint identity,
reparses them in a fresh process, and sends safe TABLE_DUMP_V2 observations
through the same normalized state admission. Collector entries remain
directionless `collector_candidate` evidence rather than captured Adj-RIB-In.
See [product/BGP_MRT_STORE.md](product/BGP_MRT_STORE.md).

## Captured BGP producer parity — source candidate

The captured producer extension in [product/BGP_PRODUCER.md](product/BGP_PRODUCER.md) stages
`decode_pcap` state until complete budget and output checks succeed. It binds
source/session/capture context, retains both OPEN directions and repeated
advertisements, exposes exact capability and path-attribute occurrences, and
leaves duplicate or unresolved scalar summaries unselected. Repeated OPENs
no longer infer a new generation. A missing session produces unknown generation,
not another session's state. Negotiation and all authority claims remain false.

Imported normalizer bytes and import/state/replay partition, clock, checkpoint
and boundary contracts remain unchanged. The new occurrence value coordinates
are validated by state admission and excluded from state/association path
identity, while their evidence is retained. Captured output gains additive fields;
strict consumers and event hashes must account for the documented migration.

The reviewed producer and pipeline pass local Windows debug/release,
no-default-feature, formatting, warnings-denied Clippy, and independent-vector
gates. Cross-platform/runtime, live, scale, fuzz, secure and normative
qualification remain open. External source verification and adapters are outside
this producer.

## Generic normalized BGP replay — source candidate

The opt-in `deep::bgp_replay` API in [product/BGP_REPLAY.md](product/BGP_REPLAY.md) wraps existing contextual
imported observations in a bounded, ordered feed envelope. It reuses source,
batch/checkpoint, clock and generation metadata; exact replay is a no-op,
changed ordered records quarantine the feed, and boundaries remain explicit.
Pages are staged through the existing candidate reducer before receipt publication.

Replay and association receipts preserve provenance and coverage. Partial or
unknown feed coverage cannot be upgraded by a final marker or caller association
context. External-source verification and the caller's adapter remain outside
this I/O-free module. There is no new CLI/event integration, dependency, endpoint
RIB, best-path, reachability, attack, causality or source-authority claim.

This addition was not covered by its original worker receipt, but it has since
passed the current local Windows native Rust and complete-checkout acceptance
gates. Broader cross-platform, corpus, scale, fuzz, security, and normative
qualification remains open. Existing BGP/DNP3 behavior is preserved.

## Candidate BGP evidence association (opt-in source candidate)

`deep::bgp_association` provides typed, bounded, read-only association between
normalized BGP route observations (or a `bgp_state::CandidateState` snapshot)
and caller-adapted internal flow/security records. An explicit `Policy` owns
namespace/session/generation/flow/direction, prefix-or-endpoint and clock-window
comparison. All compatible alternatives and unresolved witnesses are retained;
no first/last/best-path choice, source preference or causal inference is made.

See [product/BGP_ASSOCIATION.md](product/BGP_ASSOCIATION.md) for the public APIs,
versioned `pcap-evidence.bgp.association.v1` schema, input and output limits,
clock-uncertainty arithmetic, imported partition isolation, and atomic failures.
This is not automatically wired into any existing command, event, transaction,
producer, state reducer or history path. There is no new CLI flag or dependency.
External ingestion, source verification and production correlation remain caller
responsibilities. The worker could not run Rust, but the complete candidate has
since passed the local Windows native association/product/workspace gates;
Linux/macOS, live, scale, fuzz and normative qualification remain open.

## Imported BGP context (source candidate)

The opt-in `deep::bgp_import` API is specified in
[product/BGP_IMPORT.md](product/BGP_IMPORT.md). It adds typed schema/version,
clock-label uncertainty, immutable batch/hash, checkpoint, session/generation,
peer/local and source-range context. `normalize_with_context` and
`normalize_boundary` connect to `bgp_state::Observation::from_normalized` and
`CandidateState::apply` without an adapter or network operation.

`bgp::normalize_imported` keeps its signature and now emits explicit null
compatibility context and generation. Older zero-placeholder imports remain
readable. Captured/imported normalized envelopes gain null-or-typed
`import_context` and `import_boundary` fields; strict consumers and event hashes
must account for these additive fields. No automatic reducer, new CLI flag,
generic transaction or streaming confirmation change is introduced. The worker
lacked Rust tooling, but the new native tests and full local Windows validation
now pass; Linux/macOS, live, scale, fuzz and normative qualification remain
open.

The DNP3 workflow and additive fragment-confirmation source candidate are
specified in [DNP3_WORKFLOWS.md](DNP3_WORKFLOWS.md). The new public seam is
`correlate::dnp3_confirmation_candidates(&applications, &limits)`, backed by
`semantics::dnp3_workflow::verified_fragment_witness`. It returns separate,
non-causal fragment-identifier observations, not request/response transactions.

Root `Analysis` and JSON gain `dnp3_confirmation_candidates` and
`dnp3_confirmation_error`; the latter contains a typed failure and participates in
`has_diagnostics()`. Existing transaction statuses/reasons and JSON are retained.
Each verified side carries application/fragment references, addresses, captured
direction, link DIR, raw application flags/function/sequence, exact header spans,
all packet IDs and CRC-checked link-header dependencies. Unclassified references
never invent trusted header values. Captured timestamps remain in packet records.

No new flag is needed for root `analyze`. Headers are small non-secret evidence
and include hex even when bulk payload is disabled. Candidate status does not
establish receipt, causality, acceptance, device effects, authentication or
normative conformance. Exhaustive Rust `Analysis` literals need the two new fields;
no ABI compatibility is promised. The streaming crate adds a separate
`dnp3.confirmation_candidate` event projection for verified TCP fragments. It is
scoped by capture hash, session, flow window/generation, reversed individual
addresses, sequence and UNS namespace, and carries exact participant witnesses.
It never renames or mutates generic `transaction.candidate` events and never
pairs separate UDP datagrams. The worker lacked Rust, but the implementation has
been validated locally with the Windows native toolchain; Linux/macOS runner
evidence and live/scale/fuzz qualification remain open.

### Bounded DNP3 Group 0 attributes

`semantics::dnp3::decode` also accepts bounded Group 0 attribute object regions
when called with `Context::ResponseValues`. Each `attribute_value` record retains
the exact envelope range and exposes `data_type`, the encoded `length`, and a
source-bound `value`. Unsigned and signed integers use only 1/2/4-byte widths;
floats retain IEEE bit patterns at 4/8 bytes; DNP3 time is a raw 6-byte value;
known boolean variations are decoded from the signed-integer wire type. Visible
strings, octets, bit strings, unknown data types, and attribute-list payloads are
hash-only; even-width list payloads additionally emit exact `attribute_list_entry`
records. Group 0 variation 254 read requests are retained as header-only evidence
under `Context::ReadHeaders`. Invalid widths, odd list payloads, and truncation
stop at the earliest untrusted byte without resynchronizing. No attribute name,
vendor meaning, security meaning, endpoint state, or write effect is inferred.

### Bounded DNP3 Group 70 file objects

Under the `Context::ResponseValues` and `Context::FileValues` entry points, the
root semantic decoder also accepts DNP3 Group 70 free-format
qualifier `0x5B` object envelopes for variations 3--8. Each `file_object` record
retains its exact length-prefixed object span. Variations 3 and 4 expose bounded
command metadata/status; variations 5 and 6 expose file handles and full-width
block numbers; variation 7 exposes validated descriptor metadata; and variation 8
retains the specification length. Status fields and optional status text are
bounded. Filename, file specification, authentication-key, status text, and
transport content bytes are represented only by length plus SHA-256 digest.
Variation 2 authentication objects stop with an explicit unsupported result. The
opt-in product depth observer additionally correlates complete assembled Group 70
observations into bounded file-transfer candidates keyed by capture session,
endpoint pair, and file handle. It retains block hashes, gaps, duplicates,
metadata conflicts, and packet witnesses, but never exposes raw sensitive bytes,
claims endpoint acceptance/write/close effects, or treats a candidate source
coverage match as successful device behavior. Full endpoint-authoritative
transfer semantics and secure authentication remain open.

### Bounded BGP route evidence

The opt-in product depth module exposes `deep::bgp::decode_pcap` for one
already-framed BGP message and a bounded `SessionState`. OPEN capability context
is retained by direction and generation; UPDATE messages emit source-bound route
records for IPv4 and supported multiprotocol prefixes, withdrawals, path
attributes, unknown-attribute hashes, and exact message-relative ranges. OPEN,
NOTIFICATION, and ROUTE-REFRESH records also expose bounded message metadata;
a valid NOTIFICATION advances the session generation so later route evidence
cannot inherit the closed session's context. The
normalized record has explicit `captured` versus `imported` source kinds so a
caller-supplied route observation can use the same shape without becoming wire
evidence. Imported observations are marked as not wire-verified. Neither form
claims RIB installation, best-path selection, endpoint behavior, timing
causality, or complete BGP conformance. Malformed known attributes follow their
explicit offline discard, treat-as-withdraw, or session-reset disposition;
coalesced/trailing bytes are rejected at the single-message decoder boundary.

The examples below use the included API, not `pcap-parser` or libpcap APIs. They are
covered by the local native validation gate described in `VALIDATION.md`; platform-
specific and real-world qualification remain open.

## Borrowed container parsing

```rust
use pcap_evidence::capture::{CaptureIter, ParseMode};
use pcap_evidence::{Limits, Result};

fn inspect(bytes: &[u8]) -> Result<()> {
    for item in CaptureIter::new(bytes, Limits::default(), ParseMode::Strict)? {
        let record = item?;
        if let Some((meta, data)) = record.packet() {
            println!("frame={} interface={} bytes={} time={:?}",
                     meta.frame, meta.interface, data.len(), meta.timestamp);
        }
        // record.raw() preserves the entire original record/block.
        // record.offset() is the source byte offset.
    }
    Ok(())
}
```

`CaptureIter` borrows packet and raw-block bytes from its input. Section/interface
state and option metadata still need bookkeeping. A returned raw record is not an
owned packet and cannot outlive the input snapshot. Errors fuse the iterator.

## Streaming record reader

```rust
use std::fs::File;
use pcap_evidence::capture::{CaptureReader, ParseMode};
use pcap_evidence::{Limits, Result};

fn stream(path: &str) -> Result<()> {
    let input = File::open(path)?;
    let reader = CaptureReader::new(input, Limits::default(), ParseMode::Strict)?;
    for item in reader {
        let record = item?; // owns this record's bytes
        if let Some((meta, bytes)) = record.packet() {
            println!("{} {}", meta.frame, bytes.len());
        }
    }
    Ok(())
}
```

Short reads and interrupted reads are handled explicitly. The reader's configured
input/record/packet limits still apply; streaming does not disable budgets. It is
synchronous `std::io::Read`. There is no Tokio/mmap adapter advertised in this version.
The common incremental `Decoder` is the extension seam, not a duplicate parser.

## Full offline analysis and labels

```rust
use pcap_evidence::{correlate, engine::{analyze, Config}, report, Result};

fn analyze_json(bytes: &[u8], labels: Option<&str>) -> Result<String> {
    let mut analysis = analyze(bytes, Config::default())?;
    if let Some(tsv) = labels {
        correlate::apply_labels(&mut analysis, tsv)?;
    }
    report::analysis(&analysis, false).encode_bounded(64 * 1024 * 1024)
}
```

The engine consumes an immutable snapshot. It retains bounded reconstructed payload
and source spans. Reports are derived values, not authenticated declarations.
`has_diagnostics()` detects supported-path degradation; `false` does not prove the
capture includes every wire packet or that an attack was benign.

Configuration fields include limits, capture parse mode, overlap policy, checksum
policy, idle timeout in integer nanoseconds and explicit DNP3/Modbus port lists.
Protocol service-role configuration is not inferred from which side sent the SYN.

### Configured UDP DNP3 and advisory probes

When either endpoint of a decoded UDP datagram uses a configured DNP3 port,
`engine::analyze` creates one `datagram::DatagramAnalysis` entry. Its payload and
packet IDs retain the original source spans, and its DNP3 result is decoded with
fresh state for that datagram only. A UDP datagram is not treated as an ordered,
reliable stream: separate datagrams are never concatenated, retransmitted, or used
to complete one another. The JSON projection exposes these entries as
`udp_applications` and includes `reconstruction_scope` to make that boundary
machine-readable.

DNP3 frames retain their raw link-control byte and decoded direction/PRM/FCB/FCV/
DFC fields. A reserved secondary control bit or an unknown link function is
retained as evidence but adds `dnp3_reserved_link_control_bit` or
`unsupported_dnp3_link_function` to the result issues; it never authorizes a
transport or application reconstruction.

`protocol::ProbeRegistry` is an explicit extension point for bounded, read-only
prefix probes. Built-in DNP3 and Modbus probes report a structural observation and
their examined extent; they do not select the engine protocol, assign probability,
authenticate a peer, or authorize transaction correlation. A caller must provide a
contiguous prefix and inspect all returned observations when multiple probes match.

## Sidecar index

```rust
use pcap_evidence::index::{Index, VerifiedIndex};
use pcap_evidence::{Limits, Result};

fn first_packet(bytes: &[u8]) -> Result<Vec<u8>> {
    let sidecar = Index::build(bytes, Limits::default())?.encode()?;
    let verified = VerifiedIndex::load(bytes, &sidecar, Limits::default())?;
    Ok(verified.packet(1)?.to_vec())
}
```

Build/load scans source bytes. Load checks the sidecar structure and hashes, then
reconstructs canonical metadata from the exact source borrow. Only after that gate
can repeated `packet(frame)` accesses be direct indexed slices. `time_range(start_ns,
end_ns)` scans entries without assuming capture order is timestamp order; missing or
inexact times appear in `unresolved_frames` rather than disappearing.

## Writers

```rust
use pcap_evidence::capture::Endian;
use pcap_evidence::time::{Resolution, Timestamp};
use pcap_evidence::writer::PcapNgWriter;
use pcap_evidence::{Limits, Result};

fn wrap_packet(packet: &[u8]) -> Result<Vec<u8>> {
    let mut writer = PcapNgWriter::new(Vec::new(), Endian::Little, Limits::default())?;
    let interface = writer.interface(1, 65535, Resolution::Decimal(9), 0)?;
    let original = u32::try_from(packet.len())
        .map_err(|_| pcap_evidence::Error::limit("packet_bytes"))?;
    writer.packet(interface,
        Timestamp { ticks: 1_000_000_000, resolution: Resolution::Decimal(9), offset_seconds: 0 },
        original, packet)?;
    writer.finish()
}
```

This writer records bytes with caller-declared link type; it does not validate that
those bytes actually encode an Ethernet packet. Classical `PcapWriter` requires an
exactly representable timestamp; it refuses implicit sub-microsecond loss.
`copy_exact` validates an entire source before archival byte copying. It is not a
semantic edit operation that transplants do-not-copy custom extensions.

A generic `Write` failure can leave a partial output. After that failure, discard the
writer and the incomplete result. Prevalidation rejection occurs before the write
and permits a subsequent valid packet. Use `publish::write_new` to create a new
filesystem result without clobbering an existing output.

## CLI options and behavior

Use `--help` for the exact schema. Paths and arguments must be UTF-8 in the CLI;
library callers can use normal Rust path/read APIs. Flags with values accept one
occurrence. `--dnp3-port` and `--modbus-port` replace their respective default port;
use the library config for lists. No environment variable silently changes analysis.

The external label format is strict UTF-8 TSV with this header (tab separators):

```text
attempt_id	start_ns	end_ns	src_ip	src_port	dst_ip	dst_port	transport
```

Each row has a distinct ID, signed integer nanosecond start/end with `start <= end`,
exact IP addresses and ports, and `tcp` or `udp`. Bounds are inclusive; matching is
bidirectional. Wildcards, duplicate IDs, invented epoch defaults and float timestamps
are not accepted. `tests/fixtures/attempts.tsv` is an executable example.

Exit codes: **0** completed; **2** usage/label error; **3** I/O/publication failure;
**4** malformed/unsupported operation or `--require-clean` diagnostic result.
For `--require-clean`, the analysis report is still emitted before exit 4. An ordinary
`analyze` may complete with nonempty diagnostics and exit 0; consumers must inspect
report status, not infer clean evidence from successful process exit.

## Opt-in protocol depth and history

The product crate exposes pcap_evidence_product::deep for an already-framed,
source-bound EvidenceBytes unit. The caller supplies the protocol hypothesis,
Context and Limits. Reports are partial observations with exact message-relative
field ranges and explicit unsupported/incomplete/ambiguous notes.

The pcap-depth command provides deliberately separate decode, capture, and BGP
journal workflows:

    pcap-depth decode opcua_tcp unit.bin --ua-security-none
    pcap-depth analyze capture.pcap --workspace NEW_DIRECTORY --format ndjson
    pcap-depth bgp import-mrt dump.mrt --workspace NEW_DIRECTORY --source-id ID --checkpoint ID
    pcap-depth bgp replay NEW_DIRECTORY/bgp.journal --output NEW_FILE
    pcap-depth bgp state NEW_DIRECTORY/bgp.journal --output NEW_FILE
    pcap-depth bgp query NEW_DIRECTORY/bgp.journal --session N --output NEW_FILE
    pcap-depth bgp export NEW_DIRECTORY/bgp.journal --output NEW_FILE

The first command reads one standalone protocol unit and does not parse a PCAP.
The second augments the existing event pipeline after independently hashing the
complete capture and re-reading and hashing each packet. It writes a no-clobber
receipt, packet map, hash-chained event output, and sealed BGP source journal.
The BGP replay/state/query/export commands accept a sealed, internally consistent
captured journal or MRT source store and create new outputs atomically. Captured
`query` returns every retained occurrence of a reused numeric analysis-session
ID; MRT query accepts the adapter session label such as `mrt:0:0`. `export` is NDJSON; the
other commands produce one JSON document. All state remains an offline
Adj-RIB-In candidate, not endpoint truth. See
[product/BGP_STORE.md](product/BGP_STORE.md) and
[product/BGP_MRT_STORE.md](product/BGP_MRT_STORE.md).
See docs/product/DEPTH_CONTRACT.md for the supported protocol subsets and their
security, provenance and endpoint-effect boundaries.

The history-app executable consumes a sealed history workspace, verifies source
and index identities through History::evidence_range, and carries application
state across selected pages. A gap, conflict, sequence discontinuity or range
end emits an explicit boundary/incomplete event. A complete event means only
that the selected source-verified range was consumed; no endpoint history or
wall-clock replay claim is made.

## JSON representation

Report schemas are explicitly named `pcap-evidence.*.v1`. Exact timestamps and large
signed offsets are serialized as decimal strings; do not round them through JSON
floating-point numbers. Packet ordinal and record offset are distinct. Stream and
protocol byte objects carry length, digest and source spans; payload hex is opt-in
except the explicit `packet` extraction command.

Every provenance span names the original packet ID, a byte interval in the derived
object, and a starting byte offset **inside the captured packet**, not inside its
PCAP record. DNP3 CRC removal and reconstruction preserve that distinction.
`check_cli.py` reconstructs these objects from source packet slices and checks their
hashes independently. Correlation rows are named candidates, with reasons for orphan,
ambiguous, incomplete, unsupported or missing-time states.
