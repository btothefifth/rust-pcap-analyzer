# Validation and promotion gates

The supplied receipt separates authoring-host checks from native or normative
qualification. It is not a release certificate. A missing compiler is BLOCKED,
not evidence that the code compiles. Preserve every pre-existing gate.

## Apply and compile

From the integrated repository root, on an explicitly prepared Rust 1.85.1 host:

```sh
cargo fmt --all
cargo fmt --manifest-path streaming/Cargo.toml --all
cargo fmt --manifest-path fuzz/Cargo.toml --all
python scripts/update_test_manifest.py
cargo test --locked --offline --all-targets
cargo test --locked --offline --release --all-targets
cargo clippy --locked --offline --all-targets -- -D warnings
cargo test --manifest-path streaming/Cargo.toml --locked --offline --all-targets
cargo test --manifest-path streaming/Cargo.toml --locked --offline --release --all-targets
cargo clippy --manifest-path streaming/Cargo.toml --locked --offline --all-targets -- -D warnings
cargo test --manifest-path product/Cargo.toml --locked --offline --all-targets
cargo test --manifest-path product/ffi/Cargo.toml --locked --offline --all-targets
cargo test --manifest-path history/Cargo.toml --locked --offline --all-targets
python scripts/validate.py
python scripts/test_semantic_tools.py -v
cargo build --locked --offline --example semantic_probe
python scripts/semantic_case_runner.py --probe target/debug/examples/semantic_probe --output /new/native-semantic-cases.json
```

Use `.exe` for the probe on Windows. The manifest updater records source inventory,
not execution, and should run only after reviewing added test selectors. Formatting
is a development step because rustfmt was absent on the authoring host. Do not
remove or weaken failures to make a gate green. Update the current-state pointer
with fresh command/platform/toolchain/fixture receipts.

For the product consumer projection, build the product CLI and compare both output
formats with the independent TLV reader:

```sh
python scripts/validate_semantic_product.py \
  --binary product/target/debug/pcap-product \
  --output-dir /new/semantic-product-parity
```

The validator runs the five supplied semantic captures, requires a complete
source-bound event stream, decodes TLV with `tools/product/tlv.py`, and compares
the complete NDJSON/TLV event sequences. This is a local projection-consistency
gate, not normative protocol qualification or linked-ABI proof.

The new root tests cover typed fields, quotas, malformed neighbors, duplicate
indices, exact bit patterns, context forgery, request/response padding and source
spans. Capture-driven tests exercise snapshot and streaming paths, segmentation,
reordering, retransmission, conflicting overlaps, gaps, and window boundaries.
The independent case runner verifies raw field witnesses and expected values for
18 explicit payloads. Its own Python process tests are not native semantic runs.

## JSON / TLV / workbench consumers

The product TLV path inherits the existing JSON value model. The completed local
run exercised the product CLI on all five PCAP fixtures with NDJSON and TLV,
decoded TLV using the existing Python reader, and asserted complete event-sequence
parity. This is projection consistency only; native workbench, linked ABI and
normative protocol gates remain separately executable.

## Development-only fuzzing

The existing isolated `fuzz/` workspace gets a `semantics` target. It exercises
bounded DNP3/Modbus decode outcomes, deterministic projections, and source bounds.
It is not a replacement for the history state-machine target or existing wire
and container targets. In a prepared environment:

```sh
cd fuzz
cargo fuzz run semantics -- -max_total_time=3600 -rss_limit_mb=1024 -timeout=10
```

Record source/seed/toolchain identity, duration, coverage, crash artifacts and
minimized regressions. This is an example command, not a campaign receipt.

## Remaining scope

Full-history fragment/protocol continuation, additional DNP3 groups/qualifiers,
MMS/GOOSE/SV depth, complete per-family external adapters, platform packaging,
C/Linux/browser qualification, representative corpus, sustained fuzzing and
50–500 GB performance are not closed by this parser-library slice. Protocol
conformance requires edition review and independent adjudication, not agreement
with another parser or the registration of these tests.
