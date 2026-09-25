# Validation report — streaming evidence integration

**Overall disposition: PASS for the configured local Windows gate; broader
qualification remains open.**

The local host provided Python 3.12, the pinned Rust 1.85.1 toolchain and a
The local host also exercised the opt-in product-depth tests, pcap-depth
capture smoke path, sealed-history application smoke path, and optional OPC UA
transform boundary tests. Those are separate evidence classes and do not upgrade
the broader full-history, fuzz, scale, live-capture or normative gates.

Windows native linker. The root snapshot analyzer and the new `streaming/`
crate passed their configured debug/release tests, formatting and warnings-denied
Clippy checks. The Python evidence tooling and the independent root CLI oracles
also passed. This is local synthetic proof only: no cross-platform CI, fuzz
campaign, performance qualification, security audit or representative real-world
capture replay is represented as passing.

## Checks actually executed

| Surface | Observed result | What it establishes |
|---|---|---|
| Python source checks, fixture regeneration and independent reference oracle | PASS | Portable tooling and checked-in synthetic fixture truth are internally consistent |
| Root Rust check, debug/release tests, binary build and warnings-denied Clippy | PASS | Native Windows execution with Rust 1.85.1 and the configured linker |
| Root Rust test inventory | PASS, 133 collected on Windows | 135 selectors are recorded; two Unix-only selectors were not collected on Windows |
| Streaming Rust check, debug/release tests, example target, build and warnings-denied Clippy | PASS, 40 contract tests | The bounded reader/runner, event schema path, plugins and example compile and pass their local contracts |
| Root and streaming rustfmt checks | PASS | The reviewed Rust source is formatted |
| Root CLI and independent hardening CLI oracle | PASS, 93 synthetic cases | The actual compiled root CLI was compared with independent expectations |
| Python evidence-tool suite | PASS, 68 tests and 23 subtests | Indexing, chain verification, replay, minimization, corpus and process-boundary helpers pass locally |
| Semantic mutation checks | PASS, 3/3 mutants killed | Named tests detect timestamp, conflict and forged-index regressions |
| Root and streaming fuzz manifests | PASS, `cargo check` | Fuzz targets compile; no fuzz campaign or coverage claim is made |
| Streaming fixture smoke run and SQLite projection | PASS | A release CLI emitted a 31-event hash-chained log for the synthetic Modbus fixture and the source-bound index queried it |
| Source package and manifest | PASS after the package-builder fix | The deterministic archive includes reviewed `streaming/` and the public corpus manifest while excluding generated targets and non-test captures |

The exact commands, platform, timestamps, stdout/stderr and source identity are
retained in `evidence/local-validation.json`. Its current status is `PASS` and
`native_rust_executed` is true for this local run. The qualification receipt is
also retained outside the repository because it is a run artifact, not a source
contract.

## Not included in this local gate

The test inventory is not a claim that every selector ran on every platform.
Conditional tests can change collection on Linux, macOS or a different compiler.
The included workflow is configuration, not a CI result. The fuzz workspaces
compile, but no sustained fuzz campaign, coverage threshold or crash-free claim
was observed. No performance or peak-RSS qualification, security audit,
large-file run, differential semantic comparison against other analyzers, or
representative real-world capture replay is claimed. The bundled corpus is a
manifest with an optional upstream test-capture entry; it is not a representative
operational corpus and is not fetched by default.

The streaming path is deliberately bounded-window evidence analysis. It emits
explicit coverage boundaries and sets `complete_protocol_history=false` at
capture completion. It does not provide lossless full-history TCP reconstruction
across discarded windows, TLS decryption, or a sandbox for trusted in-process
plugins. See [`docs/streaming/CONTRACT.md`](streaming/CONTRACT.md).

## Repeat the local gate

From the repository root, with Python 3.11+ and the pinned Rust toolchain:

```text
python scripts/validate.py
python tools/evidence_tool.py qualify . receipts/local --timeout 600
```

The first command runs the root portable/native gate and writes a source-bound
receipt. The second runs the root and streaming qualification matrix. Neither
installs tools or silently turns an unmet prerequisite into a pass. A source
change during either run invalidates that run's receipt.

Useful individual commands are:

```text
cargo test --locked --offline --all-targets
cargo test --locked --offline --release --all-targets
cargo clippy --locked --offline --all-targets -- -D warnings
cargo test --manifest-path streaming/Cargo.toml --locked --offline --all-targets
cargo test --manifest-path streaming/Cargo.toml --locked --offline --release --all-targets
cargo clippy --manifest-path streaming/Cargo.toml --locked --offline --all-targets -- -D warnings
cargo fmt --all -- --check
cargo fmt --manifest-path streaming/Cargo.toml --all -- --check
```

## Interpretation and promotion

Portable checks reduce fixture, packaging and process-boundary mistakes. Native
synthetic tests establish the named contracts, not all network behavior. A
representative capture is still needed to validate an external mismatch. Any
cross-tool disagreement must be resolved against packet bytes, protocol rules
and independently established expectations, not majority vote or a single
decoder treated as infallible.

Source hashes, archive checksums and successful extraction establish content
identity, not correctness, authenticity of real captures, successful deployment,
or attack attribution. Read [`LIMITATIONS.md`](LIMITATIONS.md) before widening
input size or accepting untrusted uploads.
