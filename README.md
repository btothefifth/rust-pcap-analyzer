# rust-pcap-analyzer

## Restartable captured and MRT BGP state — source candidate

`deep::bgp_pipeline::CapturedSessionPipeline` now joins one framed captured BGP
message atomically across the wire decoder, offline session observer, and
Adj-RIB-In candidate reducer. It preserves source partitions and handles EOR,
NOTIFICATION/UPDATE resets, explicit gaps and transport boundaries without
claiming endpoint state or negotiation. See
[the pipeline contract](docs/product/BGP_PIPELINE.md). The `pcap-depth` event
path now owns bounded per-session pipelines and emits message receipts plus
flow-end summaries. Completed protocol messages are merged across reconstructed
TCP directions in capture-record order without disturbing per-direction TCP
sequence reassembly. Successful depth runs also publish a sealed, hash-chained
`bgp.journal` containing exact reconstructed message bytes, packet spans, and
continuity boundaries. A fresh process can verify and replay that journal into
queryable candidate state. The same commands now accept a sealed `bgp.mrt`
source store created from bounded TABLE_DUMP_V2/BGP4MP input. Safe collector RIB
entries use the same normalized observation model while retaining null direction,
source/checkpoint/range identity, and explicit non-endpoint authority. See
[the MRT store contract](docs/product/BGP_MRT_STORE.md).

## Captured BGP producer parity — source candidate

The captured producer extension in [docs/product/BGP_PRODUCER.md](docs/product/BGP_PRODUCER.md) stages
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
qualification remain open. External source verification and adapters remain
outside the producer.

## Generic normalized BGP replay — source candidate

The opt-in `deep::bgp_replay` API in [docs/product/BGP_REPLAY.md](docs/product/BGP_REPLAY.md) wraps existing contextual
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

## Generic BGP evidence association — local Windows native acceptance

The opt-in `deep::bgp_association` API relates normalized BGP route evidence to
caller-adapted internal flow/security evidence under an explicit namespace,
dimension and clock policy. It retains alternatives, conflicts, provenance and
unresolved coverage without selecting a best path, proving reachability,
causality or source authority. It does not ingest external feeds or change the
capture/CLI/event paths; source adapters and production joins remain caller
responsibilities. The complete candidate passes the local Windows native and
portable validation gates; Linux/macOS, live, scale, fuzz, security and
normative qualification remain open. See [the association API](docs/product/BGP_ASSOCIATION.md).

## Opt-in BGP candidate route state

`deep::bgp_state` now provides a separate bounded consumer of normalized captured
and imported route observations. It keeps source/session/generation/direction
isolation, replay receipts, conflict alternatives, explicit withdrawals and
boundaries without claiming an endpoint RIB, best path or source authority.
Existing decoder, CLI and event output remain unchanged. See
[the API and policy](docs/product/BGP_STATE.md); this addition is a source
candidate whose worker-authored code was reviewed and validated locally on
Windows, with cross-platform and broader conformance qualification still open.

The additive [DNP3 workflow candidate](docs/DNP3_WORKFLOWS.md) extends the reviewed
root subset without claiming full conformance. Fresh isolated Windows native
gates for this slice pass; the remaining qualification limits are documented
below and in the workflow contract.

**Offline Rust capture parsing, bounded stream reconstruction, and traceable protocol evidence.**

The repository is named `rust-pcap-analyzer`; its crate and CLI remain `pcap-evidence`.
Prepared as a generic offline capture-analysis foundation. This is an original,
dependency-free Rust library and command-line repository, not a wrapper around Arkime,
Wireshark, libpcap, or `pcap-parser`.

> **Delivery status: local validation PASS; broader qualification remains open.** The
> pinned Rust 1.85.1 toolchain and Windows native linker were available. Root and
> streaming checks, debug/release tests, formatting, warnings-denied Clippy, the
> compiled CLIs, the independent 93-case hardening CLI oracle, semantic mutation
> checks, Python evidence tests, and both fuzz-manifest compile checks passed
> locally. The root inventory has 135 selectors, 133 collected on Windows, and the
> streaming contract suite has 40 tests. Windows/Linux/macOS CI exists for the
> root and streaming contracts, but no sustained fuzz campaign, performance
> qualification, security review, or representative real-world capture replay is
> claimed. See [the exact validation boundary](docs/VALIDATION.md), the
> [streaming contract](docs/streaming/CONTRACT.md), and the retained
> [machine-readable receipt](evidence/local-validation.json). This is a working
> source baseline, not a certified or production-ready release.

## What is implemented

| Layer | Implementation | Important boundary |
|---|---|---|
| Capture containers | All four classic PCAP magic variants; PCAPNG sections, interfaces, packet blocks, metadata, unknown blocks/options; borrowed and streaming readers; new-capture writers | Raw preservation is broader than semantic decoding of every metadata option |
| Time and identity | Raw decimal/binary clocks, signed offsets, exact integer conversions, capture SHA-256, packet ordinals and byte offsets | Missing/inexact time stays unknown; the library does not synchronize clocks |
| Packet decoding | Ethernet, VLAN stacks, SLL/SLL2, raw IP, loopback; IPv4/IPv6; TCP/UDP; checksums and IP fragments | Unsupported link/protocol types are retained with a typed disposition; IPv6 fragment identity follows offset-zero protocol metadata |
| TCP reconstruction | Connection generations, sequence wrap, reordering, duplicate bytes, gaps, SYN/FIN edges, explicit conflict policies | Conservative offline inference, not emulation of every endpoint TCP implementation |
| Industrial protocols | DNP3 CRC/link/transport/application framing, sequence rollover, incomplete messages, unsolicited responses, function-code labels, indexed selectors, 1/2/4-byte ranges, bounded Group 0 attribute envelopes, bounded Group 70 free-format file metadata/content-hash evidence for variations 3--8, standard non-secure object/qualifier value subsets, variable-octet identity, CROB evidence, message-level semantic reports, and configured-port UDP datagram analysis; Modbus/TCP MBAP and common message-shape/response checks | DNP3 still has unsupported secure/authentication, Group 70 authentication variation 2, deep cross-APDU file-transfer semantics, endpoint-state, and full conformance/replay semantics; UDP datagrams never form a reliable cross-datagram stream |
| Evidence correlation | Transaction candidates, external attempt-label matching, message-to-stream-to-packet provenance | **Not attack detection, attribution, or proof that an attack succeeded** |
| Tooling | Deterministic JSON, source-bound sidecar index, no-clobber output, CLI, tests, fixtures, advisory protocol probes, fuzz harnesses, CI, independent oracles and packaging scripts | Index load verifies/re-parses the source; large-file analysis is not an out-of-core engine |

No live capture, traffic injection, remote service, database, credentials, telemetry,
or network access is part of the runtime.

## Bounded streaming analysis

The sibling `streaming/` crate reads a capture incrementally and emits typed,
hash-chained NDJSON evidence without constructing one capture-sized report tree:

```sh
cargo run --manifest-path streaming/Cargo.toml --release -- analyze capture.pcap \
  --run-id local-run --output events.ndjson
```

It supports bounded active flows, payload, packet and window budgets, explicit
`coverage.boundary` events, and source binding at `capture.complete`. A window
cut discards reconstruction history by design; the completion event therefore
sets `complete_protocol_history=false`. This is useful for inspectable bounded
analysis of large inputs, not a claim of lossless full-history reconstruction,
TLS decryption, live capture, or a plugin sandbox. See
[`docs/streaming/CONTRACT.md`](docs/streaming/CONTRACT.md).

For DNP3, the streaming path also emits a separate
`dnp3.confirmation_candidate` projection from CRC-verified TCP fragments. It is
bounded to one capture/session/window/generation and retains exact participant
evidence; it does not alter generic transaction events or pair separate UDP
datagrams. The projection is an identifier candidate, not proof of receipt,
causality, device acceptance, or physical effect.

## Product workspace and local workbench

The opt-in pcap-depth binary adds deeper, still-partial protocol observations
and the standalone history-app consumer applies those observations to sealed,
source-verified history ranges. These layers do not change the core parser's
dependency or evidence contracts.

The additive `product/` workspace layers bounded protocol observations, typed
binary output, research comparison and a separate product CLI over the core and
streaming crates. `tools/desktop/` and `desktop/web/` provide an optional local
workbench with isolated workers, source-bound evidence, history/research views and
bounded queries. These layers do not change the core parser's dependency or
evidence contracts.

```sh
cargo test --manifest-path product/Cargo.toml --locked --offline --all-targets
cargo build --manifest-path product/Cargo.toml --locked --offline --release
cargo test --manifest-path history/Cargo.toml --locked --offline --all-targets
cargo check --manifest-path history-app/Cargo.toml --locked --offline --all-targets
python -m unittest discover -s tools/tests -p 'test_*.py' -v
node --test desktop/web/model.test.mjs
```

Read [`docs/product/IMPLEMENTATION_HANDOFF.md`](docs/product/IMPLEMENTATION_HANDOFF.md)
for the design reconciliation, remaining gaps and the next implementation package.

## Get started

For a first opt-in run on a PCAP, keep the output directory new and run:

    cargo run --manifest-path product/Cargo.toml --locked --offline --bin pcap-depth -- analyze capture.pcap --workspace depth-run --format ndjson

This produces a source-bound receipt, packet map, hash-chained event file, and
sealed BGP source journal. Rebuild or inspect captured BGP candidate state in a
fresh process with no-overwrite outputs:

    cargo run --manifest-path product/Cargo.toml --locked --offline --bin pcap-depth -- bgp state depth-run/bgp.journal --output bgp-state.json
    cargo run --manifest-path product/Cargo.toml --locked --offline --bin pcap-depth -- bgp query depth-run/bgp.journal --session 1 --output bgp-session.json
    cargo run --manifest-path product/Cargo.toml --locked --offline --bin pcap-depth -- bgp export depth-run/bgp.journal --output bgp-export.ndjson

Import an external MRT batch into a new, sealed workspace and use the same
state/query/export verbs without relabeling collector candidates as captured
Adj-RIB-In state:

    cargo run --manifest-path product/Cargo.toml --locked --offline --bin pcap-depth -- bgp import-mrt dump.mrt --workspace mrt-run --source-id collector-a --checkpoint dump-1
    cargo run --manifest-path product/Cargo.toml --locked --offline --bin pcap-depth -- bgp state mrt-run/bgp.mrt --output mrt-state.json
    cargo run --manifest-path product/Cargo.toml --locked --offline --bin pcap-depth -- bgp query mrt-run/bgp.mrt --session mrt:0:0 --output mrt-peer.json
    cargo run --manifest-path product/Cargo.toml --locked --offline --bin pcap-depth -- bgp export mrt-run/bgp.mrt --output mrt-export.ndjson

The default parser remains the right starting point for general capture
inspection; depth is an explicit second pass and remains partial.

Install the Rust toolchain pinned in `rust-toolchain.toml` (**1.85.1**) through your
normal trusted installation process. Python **3.11+** is used for repository tooling;
the application does not need Python. Root Cargo builds and ordinary tests have no
third-party dependencies and are designed to work offline once Rust is installed.

```sh
cd pcap-evidence
cargo check --locked --offline --all-targets
cargo test --locked --offline --all-targets
cargo build --locked --offline --release --bins
python scripts/validate.py
```

The validation script does not install missing tools or silently skip native proof.
An absent compiler returns **2 / BLOCKED**. A real failing check returns **1 / FAIL**.

For the optional Windows native C-ABI gate, install the Visual Studio 2022 Build
Tools C++ workload and Windows SDK, then run from an x64 MSVC developer shell:

```bat
call "%ProgramFiles(x86)%\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
cargo build --manifest-path product/ffi/Cargo.toml --locked --offline
python scripts/check_linked_abi.py --compiler cl.exe --library product\ffi\target\debug\pcap_evidence_ffi.lib --output C:\Temp\pcap-linked-abi
```

The optional fuzz targets require a supported nightly Rust toolchain, LLVM and
`cargo-fuzz`; the pinned dev graph can be build-checked without running a fuzz
campaign:

```sh
cd fuzz
cargo +nightly fuzz build semantics
```

Analyze the synthetic DNP3 fixture, including externally supplied labels:

```sh
cargo run --locked --offline -- analyze tests/fixtures/dnp3_tcp.pcap --labels tests/fixtures/attempts.tsv -o analysis.json
```

`analysis.json` must not already exist: outputs are deliberately no-clobber. To emit
to standard output, omit `-o`. Output contains no packet payload by default. Adding
`--include-payload` exposes captured/reconstructed packet bytes; embedded PCAPNG
Decryption Secrets Blocks remain redacted in JSON.

When a UDP endpoint uses a configured `--dnp3-port`, `analyze` adds a
`udp_applications` array. Each entry is decoded from exactly one reconstructed UDP
datagram, retains all contributing packet IDs and source spans, and records whether
the DNP3 message is complete. Separate UDP datagrams are never concatenated or
correlated as a reliable stream.

```sh
cargo run --locked --offline -- inspect tests/fixtures/mixed_sections.pcapng
cargo run --locked --offline -- index tests/fixtures/mixed_sections.pcapng -o capture.pcidx
cargo run --locked --offline -- verify-index tests/fixtures/mixed_sections.pcapng --index capture.pcidx
cargo run --locked --offline -- packet tests/fixtures/mixed_sections.pcapng --index capture.pcidx --frame 1
```

`packet` intentionally returns packet bytes in JSON; its frame number is a **1-based
packet ordinal**, not a PCAPNG block number. A sidecar's self-hash is never sufficient
for trust: loading verifies the source identity and reconstructs canonical metadata.

For damaged or contradictory captures, `--evidence` preserves structurally readable
length/time anomalies as diagnostics. Structural corruption remains an error. It is
not automatic repair or a guarantee that every damaged file can be recovered.

## Library use

```rust
use pcap_evidence::{capture::{CaptureIter, ParseMode}, Limits, Result};

fn count_packets(bytes: &[u8]) -> Result<usize> {
    let mut packets = 0;
    for record in CaptureIter::new(bytes, Limits::default(), ParseMode::Strict)? {
        let record = record?;
        if let Some((metadata, packet_bytes)) = record.packet() {
            assert_eq!(packet_bytes.len(), metadata.captured_len as usize);
            packets += 1;
        }
    }
    Ok(packets)
}
```

See [API examples](docs/API.md), `examples/analyze.rs`, and
`examples/stream_records.rs`. The borrowed reader avoids packet-buffer copies;
streaming records own their bytes. The reconstruction pipeline deliberately retains
bounded state and payload, rather than advertising end-to-end zero-copy.

## Repository map

- `src/`: parser, writers, timestamps, packet decoders, IP/TCP reconstruction,
  DNP3/Modbus, provenance, index, correlation, JSON and CLI.
- `streaming/`: bounded reader/runner, event schema, detector registry, built-in
  protocol plugins, CLI, example plugin and optional fuzz targets.
- `tests/`: native contract, integration, hostile-input and process tests;
  synthetic fixtures, independent truth and an exact test-selector inventory.
- `scripts/`: fixture builder, independent Python oracle, black-box CLI comparison,
  mutation checks, validation receipts, benchmark and deterministic ZIP packaging.
- `fuzz/`: optional, separately dependent libFuzzer targets.
- `corpus/`: public-safe manifest only; captures are not fetched or shipped by
  default.
- `tools/`: optional evidence indexing, qualification, corpus, differential and
  minimization tooling.
- `docs/`: controlling engineering contract, API, formats, limits, validation and
  source references. `docs/CURRENT.md` is the thin current-state pointer.
- `evidence/`: actual local receipts and source-file integrity manifest; never a
  substitute for missing native or representative-corpus evidence.

## Accuracy and privacy policy

The default conflicting-overlap policy emits a gap rather than choosing convenient
bytes. Explicit `--overlap first` and `--overlap last` retain conflict diagnostics.
Checksums are observed rather than rejected by default because capture location and
offload affect their interpretation. `--strict-checksums` changes that policy
explicitly. Neither policy repairs a bad clock or recovers uncaptured data.

An attempt label is an external claim. Matching its tuple and inclusive time window
creates **candidate evidence**, not an authoritative attack/session identity.
Unknown timestamps and ambiguous connection generations are separately represented.
The report does not invent confidence percentages, fill missing fragments, or equate
one session with one attack.

Only synthetic fixtures ship in this repository. Real captures may contain secrets
and personal data even without payload export. Analyze them locally under the
appropriate authority and do not attach them to public issue reports.

## Engineering reference and license

The concrete invariants and tests are mapped in [ENGINEERING.md](docs/ENGINEERING.md).
The repository keeps its design notes self-contained and does not vendor external
operating manuals or implementation text.

Original repository source is offered under [MIT](LICENSE). There are no runtime or
ordinary-test dependency license fees. Optional fuzz tooling has its own upstream
license/dependency surface; infrastructure and maintenance remain your responsibility.
The package is `publish = false` until the owners choose a release identity and pass
the publication gates.
