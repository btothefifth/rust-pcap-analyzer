# Cleanup audit

## Scope

The cleanup branch starts at GitHub `main` commit
`1d41a6d6ce91983dcba28f7e7cb85b4584d1b650`. The local directory initially held
T3 starter files. Those files were backed up in `.git/initial-scaffold` before
checking out the fetched repository.

The audit covers the existing implementations across the six runtime Rust
workspaces and their supporting tools. It uses repository-wide risk-based
inspection, selected deep code traces, regression tests, and the existing
validation drivers. Unfinished protocol profiles retain their documented scope.

## Findings and repairs

- Modbus correlation accepted public application values with conflicting
  protocol or direction metadata. Same-direction request and response values
  could produce a candidate pair. Admission now checks protocol and direction,
  and same-direction pairs produce an ambiguous result. The regression exercises
  both valid direction assignments and invalid metadata on either side.
- Desktop time queries applied their lower and upper bounds to separate packets.
  An event with packets at times 10 and 30 matched both 15–25 and the inverted
  interval 25–15. The query now requires a contributing packet within both
  inclusive bounds and rejects inverted intervals. This follows the existing
  evidence-index query semantics. Tests cover equality and one-sided bounds.
- Runtime validation selected `--all-targets` without a separate doctest run.
  All six workspace selectors now include `cargo test --doc`. The root driver
  also checks formatting directly. A selector regression preserves these gates.
- Contributor commands were out of date. The guide now documents strict Clippy,
  formatting, doctests, workspace selection, and the existing full validator.
  The `has_diagnostics` API comment now describes the returned boolean correctly.

## Review and proof

The first independent review inspected the baseline and requested the two
behavioral repairs above. Its coverage included capture parsing, wire and
fragment handling, TCP, Modbus, correlation, provenance, clocks, publication,
indexing, streaming, history, history-app, product BER/TLV and FFI, selected BGP
parsing/policy/persistence paths, and Python query/research tooling.

Both behavioral regressions failed against the original implementations.
The initial broad validation run passed its portable preflight and root and
streaming gates before being deliberately interrupted during product compilation
to apply the repairs. Its partial receipt is retained locally and does not
represent a completed validation run.

The second independent review of commit
`dd37b6a444a4e8d711ebcb7eed407022caee586a` found no remaining actionable changes
across all 13 changed files and their callers. It independently ran the desktop
and validation-selector suites plus 36 signed timestamp query cases.

Validation on that source passed all 56 gates in `scripts/validate_product.py`,
all 16 steps in `scripts/validate.py`, and `cargo doc --locked --offline --no-deps`.
The full driver exercised formatting, strict Clippy, debug/release tests and
doctests across six runtime workspaces, six product feature profiles, portable
checks, native semantic checks, and the linked C ABI. Both drivers reported
unchanged source during execution. Validation used Rust 1.85.1 on Linux.

One earlier final-validation attempt failed in the unchanged nested
`test_timeout_kills_descendant_after_leader_exit_and_drains` fixture. The focused
selector, its outer-runner witness, the eight-test package suite, and the full
56-gate rerun subsequently passed. The failure was intermittent and its root
cause remains undetermined. The test and its thresholds remain intact.

Local receipts are in `.git/cleanup-validation-retry/summary.json` and
`.git/cleanup-root-validation.json`. Earlier adverse attempts are retained beside
them. This final status update changes documentation only. Hosted PR checks are
reported separately by GitHub.

## Evidence limits

The audit used selected deep traces across the repository. It does not establish
exhaustive line-by-line coverage, normative protocol conformance, sustained fuzz
coverage, large-capture performance, or Windows/macOS runtime behavior. Existing
qualification gaps remain documented in the current implementation pointer.
