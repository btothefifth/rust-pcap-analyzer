# Follow-up qualification and continuation

## Ordinary integrated gates

Run from a checkout with this candidate applied. All output paths below are NEW
paths under a trusted existing parent. Do not install or fetch dependencies from a
validation script. Prepare toolchains separately through the operator's trusted process.

```sh
cargo fmt --manifest-path history/Cargo.toml --all
cargo fmt --manifest-path product/Cargo.toml --all
python scripts/validate_followup.py --output /new/followup-validation
python scripts/validate_product.py --output /new/product-validation
python scripts/validate.py
python -m unittest discover -s tools/tests -v
node --test desktop/web/model.test.mjs
python -m tools.research audit
```

The follow-up driver records root/streaming/product/FFI/history format, debug,
release and warnings-denied Clippy checks separately. Run the existing product
feature matrix too; its scope is not replaced by the new driver. The driver exits
2/BLOCKED when required tools are unavailable and 1/FAIL on real failures. NOT_RUN
classes are explicitly listed, not converted into success.

The integrated Windows run on 2026-09-19 recorded 26 required PASS gates,
including the real linked C ABI harness after preparing the x64 MSVC developer
environment. Six independent classes (browser-to-native, sustained fuzz, 50-500 GiB scale,
normative review, install/upgrade/uninstall and authorized NIC capture) remain
NOT_RUN in that driver. The baseline validator and the full product qualification
matrix also passed their portable/native Rust checks. A separate direct browser
smoke run passed with real requests, native-worker source binding and keyboard
navigation; it is not a substitute for the broader packaging/accessibility gate.

## Tier-A semantic evidence

The current integration includes a bounded semantic slice rather than a claim of
complete protocol support. Run its independent native and projection checks with
fresh output paths:

```sh
python scripts/test_semantic_tools.py -v
cargo build --locked --offline --example semantic_probe
python scripts/semantic_case_runner.py \
  --probe target/debug/examples/semantic_probe \
  --output /new/native-semantic-cases.json
python scripts/validate_semantic_product.py \
  --binary product/target/debug/pcap-product \
  --output-dir /new/semantic-product-parity
```

The completed Windows receipt contains 18/18 native semantic cases and complete
NDJSON/TLV event-sequence parity for five semantic captures. It covers DNP3
per-fragment object selection and Modbus bit/register semantics through the root,
streaming and product projections. It does not prove normative conformance,
cross-fragment DNP3 joining, complete application protocols or large-capture
performance. The semantic fuzz target builds with the approved local Rust nightly
and `cargo-fuzz 0.12.0` (`cargo +nightly fuzz build semantics`) and passes
warnings-denied Clippy. Windows `cargo test` for libFuzzer bins is not the fuzz
runner; use `cargo-fuzz`. No sustained fuzz campaign is claimed.

## Native history / independent witness validation

For every `history/fixtures/*.pcap`, build a NEW history and a NEW replay using
`pcap-history`, then run `python -m tools.history_native SOURCE HISTORY`.
Use hot-tuples=1, sort-entries=2 and frequent checkpoints on the interleaving case
to force eviction and multi-pass sorting. Confirm late conflicts expose alternatives,
not merged invented bytes. Test source mutation, damaged caches/journals/indexes,
quota exhaustion, cancellation and explicit torn-tail recovery. A native helper
must reproduce decisions exactly; the Python verifier does not adjudicate TCP policy.

`history/tests/` and CLI tests cover these contracts; their existence is not a pass.
Record actual compiler, binary/source hashes, commands and results. Force multi-wrap
traffic under both strict and explicitly assumed nearest-frontier policies. Report
unassigned/ambiguous placements and application coverage, not merely packet counts.

## C ABI link and execution

```sh
cargo build --manifest-path product/ffi/Cargo.toml --locked --offline
python scripts/check_linked_abi.py --output /new/linked-abi
```

On Windows use the prepared MSVC developer environment, or pass an explicit compatible
`--compiler` and `--library` import library. On POSIX the real shared library is linked
with a local rpath. No mock implementation is permitted. The C source checks caller
allocation/ownership, limits, exact output, stale handles and concurrency; it cannot
validate arbitrary non-null pointers or establish immunity to allocation aborts.

For the current Windows toolchain, the explicit form is:

```bat
call "%ProgramFiles(x86)%\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
cargo build --manifest-path product/ffi/Cargo.toml --locked --offline
python scripts/check_linked_abi.py --compiler cl.exe --library product\ffi\target\debug\pcap_evidence_ffi.lib --output C:\Temp\pcap-linked-abi
```

The Windows harness link includes `ws2_32`, `userenv` and `ntdll`, which are
required by the Rust standard-library symbols used by this FFI artifact. The
current Windows receipt passes link and execution; this does not qualify Linux
or other calling conventions.

## Actual browser-to-native gate

```sh
cargo build --manifest-path product/Cargo.toml --locked --offline
python scripts/check_browser_native.py --engine /path/to/pcap-product --output /new/browser-native
```

Use the actual binary name declared in the product manifest. Installed Playwright
and Chromium are optional test dependencies, never shipped core dependencies.
The script starts the real local server, clicks the real UI, waits for the native
worker, validates the source binding, navigates packet rows by keyboard and opens
the checked source-byte inspector. It does not mock requests or fall back to the
Python container mode. Policy-blocked loopback/browser absence is BLOCKED; application
or engine failures are FAIL. A screenshot alone is not this gate. Packaging, upgrades,
uninstall, file associations, signing and full accessibility remain separate.

## Research artifact compatibility

New comparisons emit research-differential.v2. Existing v1 report reproduction is
preserved exactly for old bundles. Do not rewrite stored v1 reports under v2 and
call their hash drift corruption. Missing prior fields/current-layer partial coverage
blocks the stronger earliest-prefix claim. Arrays and competing interpretations
remain ordered evidence. Rehashed false raw witnesses must still fail verification.

## Still-open engineering, in dependency order

1. Review the completed native checks and repair this candidate before broadening
   it. Review the history generation policy against RFC 9293 sections 3.4/3.6,
   RFC 1982 and adversarial
   endpoint captures. These sources describe serial/transport principles; the
   nearest-frontier research policy is not an RFC conformance claim.
2. Add disk-backed IP-fragment state and complete application-parser continuation
   driven by journal intervals. Explicitly propagate generation/epoch alternatives,
   FIN conflicts and gaps; never concatenate across ambiguity to satisfy a decoder.
3. Add efficient checkpoint resume only with independently verified state/journal
   commitments. Current recovery intentionally replays source prefixes.
4. Extend high-value DNP3 objects beyond the current per-fragment slice, then add
   BACnet segmentation, connected CIP and MMS session/presentation subsets with
   primary normative fixtures. Do not inflate the support table or equate labeled
   capture folders with decoded semantics.
5. Measure progressively larger same-policy workloads: few/many tuples, long streams,
   wrap/reuse/delay, fragments/tunnels, small/large frames, gaps/conflicts, NDJSON/TLV,
   history queries/replay and output/index amplification. Retain named hardware,
   warmup/repetition variation, process-tree RSS, logical/allocated disk peaks and
   coverage losses. This candidate has no 50–500 GiB or packet-rate pass.
6. Run sustained native fuzz/sanitizer campaigns and independent analyzer adapters,
   minimize findings, adjudicate against specifications/bytes/state, and retain each
   confirmed defect as a regression. No tool votes establish correctness.
7. Qualify linked ABI and actual authorized Linux NIC acquisition separately. Do not
   promote injected privilege failure to successful live capture. Keep Windows
   descendant containment and OS packaging/security review explicit.

Primary references: https://www.rfc-editor.org/rfc/rfc9293.html and
https://www.rfc-editor.org/rfc/rfc1982.html . These are research/specification sources,
not third-party runtime parsing dependencies.
