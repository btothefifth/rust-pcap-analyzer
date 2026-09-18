# Optional coverage-guided fuzzing

These are real cargo-fuzz/libFuzzer targets, excluded from the zero-dependency
production workspace. `libfuzzer-sys` is pinned to 0.4.10. A fuzz lockfile has NOT
been resolved here, and this campaign has NOT been executed. Resolve/review the
dev-only dependency graph and record the exact approved nightly/cargo-fuzz build
before retaining a fuzz receipt.

With cargo-fuzz and a supported nightly already installed:

```sh
cargo +nightly fuzz run capture -- -max_total_time=300 -rss_limit_mb=2048
cargo +nightly fuzz run engine -- -max_total_time=300 -rss_limit_mb=2048
```

Use only synthetic or explicitly authorized sanitized corpus bytes. Reproduce
crashes as ordinary deterministic Rust tests at the earliest owning boundary.
Existing `tests/hostile_inputs.rs` covers bounded prefix/mutation families without
any third-party dependency; it is not a substitute for a sustained fuzz campaign.
