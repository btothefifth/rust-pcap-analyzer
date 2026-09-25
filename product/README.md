# PCAP evidence product — additive candidate 0.2.0

A std-only Rust product workspace using `pcap-evidence` at `..` and
`pcap-evidence-stream` at `../streaming`. Keep those independent engine crates.
This workspace adds bounded framing subsets, extension adapters, supplemental L2
observations, typed binary output and a separate CLI. It does not claim complete
protocol or automatic full-history semantics.

Build instructions: `../docs/product/VALIDATION.md`.
Protocol depth: `../docs/product/PROTOCOLS.md`.
Exact status/continuation: `../docs/product/STATUS.md`.
GUI: `../docs/product/GUI.md`.
Research: `../docs/product/RESEARCH.md`.

```sh
cargo build --manifest-path product/Cargo.toml --release --locked --offline
product/target/release/pcap-product analyze sample.pcap --profile ics-full -o new.events.ndjson
```

The source is an integration candidate. Local Rust format, debug/release test,
feature-matrix, build and warnings-denied Clippy checks pass with the declared
toolchain. See `../docs/product/STATUS.md` for the remaining C, Linux, browser,
full-history, scale, fuzz and normative-qualification boundaries.
