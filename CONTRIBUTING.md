# Contributing

Start with `docs/implementation/CURRENT.md` for current work and
`docs/ENGINEERING.md` for the implementation contract.

Use the Rust toolchain pinned in `rust-toolchain.toml` and Python 3.11 or later.
Keep changes focused, preserve source spans, and return typed errors for invalid
input. For a bug fix, add a regression that fails on the original code and
check that the nearest valid input still works.

## Local checks

Format the workspace you changed, then run its checks. For the root crate, use

```sh
cargo fmt --all
cargo clippy --locked --offline --all-targets -- -D warnings
cargo test --locked --offline --all-targets
cargo test --locked --offline --doc
```

For another workspace, add `--manifest-path`, for example

```sh
cargo fmt --manifest-path product/Cargo.toml --all
cargo clippy --manifest-path product/Cargo.toml --locked --offline --all-targets -- -D warnings
cargo test --manifest-path product/Cargo.toml --locked --offline --all-targets
cargo test --manifest-path product/Cargo.toml --locked --offline --doc
```

The root validation driver checks fixtures, formatting, debug and release tests,
doctests, Clippy, CLI behavior, and mutation tests. It saves a JSON receipt.

```sh
python3 scripts/validate.py
cargo doc --locked --offline --no-deps
```

The repository-wide driver covers all six runtime workspaces, product feature
profiles, Python and JavaScript tests, and the linked C ABI. Provision the
pinned test-only dependencies before running its offline checks. Choose a new
output directory for each run.

```sh
python3 -m pip install -r scripts/requirements-qualification.txt
CARGO_TARGET_DIR="$PWD/target" python3 scripts/validate_product.py --output evidence/cleanup-check
```

When adding, renaming, or removing Rust tests, update and review the selector
manifest with `python3 scripts/update_test_manifest.py`. CI checks the manifest
without regenerating it.

## Fixtures and scope

Fixtures are synthetic. Derive expected results from the protocol contract or an
independent oracle. Review changes to `TRUTH.json` separately from parser output.

Keep real captures, credentials, generated output, and build directories out of
commits. Third-party material requires its own redistribution permission.

Optional fuzz workspaces and external comparators have separate dependencies.
See `fuzz/README.md`. Record platform, corpus, scale, and fuzz coverage with the
commands and source revision actually tested.
