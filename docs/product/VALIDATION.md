# Qualification plan and interpretation of receipts

Run from the integrated repository:

```sh
python scripts/validate_product.py --output /new/validation-run
python -m unittest discover -s tools/tests -v
node --test desktop/web/model.test.mjs
python -m tools.research audit
```

The driver runs root, streaming, product and FFI manifest checks separately because
these are separate workspaces. It also tests each product feature selection and
performs C header/injected Linux denial gates where supported. It does not install
tools or fetch dependencies. Missing native tooling or a missing parent checkout
returns BLOCKED/exit 2. A failing check returns FAIL/exit 1. `--portable-only` changes
the declared scope, not native status. `--gui-render` requires optional Playwright
and an installed Chromium and explicitly tests offline rendering, not live IPC.

## Native required commands

```sh
cargo test --manifest-path product/Cargo.toml --locked --offline --all-targets
cargo test --manifest-path product/Cargo.toml --locked --offline --release --all-targets
cargo clippy --manifest-path product/Cargo.toml --locked --offline --all-targets -- -D warnings
cargo fmt --manifest-path product/Cargo.toml --all -- --check
cargo test --manifest-path product/ffi/Cargo.toml --locked --offline --all-targets
python scripts/validate.py
```

Retain the existing repository's streaming/independent-oracle/hardening gates. The
new fixture source and cases do not replace those. The current Windows integration
has passed the repository-wide Rust format, debug/release, build, feature-matrix
and warnings-denied Clippy checks with the pinned toolchain. Keep the explicit PATH
setup required by Rustup on machines where `cargo` is not on the inherited process
PATH. Never loosen expected truth or delete tests to get green.

## Fuzzing

`product/fuzz/` isolates its development dependency (`libfuzzer-sys`) from ordinary
runtime builds. Install/cache fuzz tooling through an explicit trusted process.
A reproducible campaign should record source/config identities, compiler, target,
seed hashes, time budget, coverage, sanitizer options, artifacts and minimized
regression identities. Ordinary builds do not download fuzz dependencies.

```sh
# In a prepared POSIX fuzz environment, from product/fuzz:
cargo fuzz run research -- -max_total_time=3600 -rss_limit_mb=2048 -timeout=10
```

This command is an example bounded campaign, not a claim it was run. Add dedicated
stateful fragment/TCP/application targets and adversarial corpus seeds in addition
to generic mutation coverage. Promote confirmed defects into deterministic tests.

## Scale measurement

The inherited `tools.evidence.benchmark` generator/runner is included for controlled
synthetic workloads. Its single-workload throughput must not be extrapolated into
50–500 GB qualification. It does not currently measure every child's RSS or all
workspace amplification. Expand the measured matrix to small/many flows, long-lived
TCP, tuple reuse, delayed packets, fragments, tunnels, duplicate/conflict rates,
NDJSON/TLV, indexing, archive/replay and malformed cases.

Record hardware, OS, compiler/build flags, source and executable hashes, commands,
warmup, repetition variance, input bytes, packets, output bytes, peak process-tree
RSS, disk high-water mark, window cuts, lost protocol coverage and replay cost.
Test disk quota/full conditions and cancellation/restart. Full-history comparisons
need independently checked same-policy semantics, not just retained source bytes.

## Keep these evidence classes distinct

Python fixture/tool tests; native Rust tests; independent real corpus runs; C header
compilation; linked ABI execution; injected live failure; actual authorized NIC
capture; UI model tests; offline renderer tests; real browser-to-native workflow;
sustained fuzz campaigns; specification adjudication; performance and OS packaging.
None is a substitute for another. The supplied screenshots use synthetic capture
traffic and a deliberately altered comparison; they are not a discovered parser bug.
The supplied YouTube reference was not retrievable and is not represented as reviewed.
