# Contributing

Start at `docs/CURRENT.md` and the controlling contract in `docs/ENGINEERING.md`.
Do not use a green fixture self-hash or a high test count as a correctness claim.

For a change, name the invariant, its smallest owner, an independent expected
result, the nearest valid case that must remain accepted, and a counterexample.
Keep raw observation, reconstruction policy, and external labels separate. Prefer
exact typed errors over silent fallback, and preserve source spans in transformations.

Run, in increasing cost order:

```sh
python scripts/static_check.py
python scripts/make_fixtures.py --check
python scripts/reference_verify.py
python scripts/test_oracle.py
cargo check --locked --offline --all-targets
cargo test --locked --offline --all-targets
cargo test --locked --offline --release --all-targets
cargo clippy --locked --offline --all-targets
cargo build --locked --offline --bins
python scripts/check_cli.py
python scripts/mutation_check.py
cargo doc --locked --offline --no-deps
```

`python scripts/validate.py` orders the main gates and retains output. Do not install
an unpinned tool in the middle of validation. Format source using the pinned
`cargo fmt` before a reviewed release; the current baseline has a passing formatting
check recorded in `docs/VALIDATION.md`.

When native tests are added/renamed/removed, intentionally run
`python scripts/update_test_manifest.py` and review its delta. Ordinary validation
checks, rather than regenerates, that inventory. `cfg(unix)` tests apply only on Unix.

Fixtures are synthetic. Keep `TRUTH.json` independently reviewed, not mechanically
generated from the Rust result. Updating both the implementation and oracle to the
same unverified assumption does not establish agreement with the specification.
Retain a targeted semantic mutant when changing an important guard. A compilation
failure is not a successful semantic mutation test.

The optional fuzz workspace needs separately installed nightly/cargo-fuzz tooling
and dependency review. See `fuzz/README.md`. Long fuzz campaigns, real-corpus replay,
Windows/macOS verification, scale tests and security review must have their own
receipts before they are claimed.

Do not add real captures, credentials, decrypted secrets, local outputs, `target/`,
or unrelated local policy/configuration sources to commits. Third-party material
remains subject to its own license; this project's MIT file does not grant rights to
redistribute it.
