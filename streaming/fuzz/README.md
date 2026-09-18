# Optional fuzz workspace

Dependencies and nightly tooling are deliberately outside ordinary builds. This
handoff did not execute libFuzzer. Harness presence is not a fuzz qualification.
On an authorized POSIX worker with an approved/cached toolchain and dependencies:

```sh
cd streaming
cargo +nightly fuzz run streaming -- -max_total_time=3600 -timeout=10 -rss_limit_mb=1024 -max_len=65536
cargo +nightly fuzz run protocols -- -max_total_time=3600 -timeout=10 -rss_limit_mb=1024 -max_len=65536
cargo +nightly fuzz run network -- -max_total_time=3600 -timeout=10 -rss_limit_mb=1024 -max_len=65536
```

Retain stdout/stderr, dependency lock, exact rustc version, source commit, corpus
hashes, exec counts, duration, coverage and artifacts. Minimize a discovered crash
with `cargo +nightly fuzz tmin TARGET ARTIFACT`, reproduce it under a native
regression test and add a valid neighbor. Do not merely assert that it no longer
panics: verify correct interpretation/provenance and budget behavior. Also run the
original repository's existing fuzz targets; these new targets do not replace them.
