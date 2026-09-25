# Optional coverage-guided fuzzing

These are real cargo-fuzz/libFuzzer targets, excluded from the zero-dependency
production workspace. `libfuzzer-sys` is pinned to 0.4.10 and the dev-only graph
is pinned by `Cargo.lock`. On the current Windows host, Rust nightly 1.100.0 and
`cargo-fuzz 0.12.0` successfully build the `semantics` target. That is a build
receipt only; no sustained fuzz campaign has been executed.

With cargo-fuzz and a supported nightly already installed:

```sh
cargo +nightly fuzz run capture -- -max_total_time=300 -rss_limit_mb=2048
cargo +nightly fuzz run engine -- -max_total_time=300 -rss_limit_mb=2048
```

Use only synthetic or explicitly authorized sanitized corpus bytes. Reproduce
crashes as ordinary deterministic Rust tests at the earliest owning boundary.
Existing `tests/hostile_inputs.rs` covers bounded prefix/mutation families without
any third-party dependency; it is not a substitute for a sustained fuzz campaign.
