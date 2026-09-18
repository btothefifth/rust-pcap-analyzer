# rust-pcap-analyzer

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
> streaming contract suite has 40 tests. No cross-platform CI, fuzz campaign,
> performance qualification, security review, or representative real-world capture
> replay is claimed. See [the exact validation boundary](docs/VALIDATION.md), the
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
| Industrial protocols | DNP3 CRC/link/transport/application framing, sequence rollover, incomplete messages, unsolicited responses, and configured-port UDP datagram analysis; Modbus/TCP MBAP and common message-shape/response checks | DNP3 object bodies and many application semantics remain opaque; UDP datagrams never form a reliable cross-datagram stream |
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

## Product workspace and local workbench

The additive `product/` workspace layers bounded protocol observations, typed
binary output, research comparison and a separate product CLI over the core and
streaming crates. `tools/desktop/` and `desktop/web/` provide an optional local
workbench with isolated workers, source-bound evidence, history/research views and
bounded queries. These layers do not change the core parser's dependency or
evidence contracts.

```sh
cargo test --manifest-path product/Cargo.toml --locked --offline --all-targets
cargo build --manifest-path product/Cargo.toml --locked --offline --release
python -m unittest discover -s tools/tests -p 'test_*.py' -v
node --test desktop/web/model.test.mjs
```

Read [`docs/product/IMPLEMENTATION_HANDOFF.md`](docs/product/IMPLEMENTATION_HANDOFF.md)
for the design reconciliation, remaining gaps and the next implementation package.

## Get started

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
