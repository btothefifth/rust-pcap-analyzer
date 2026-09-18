# CURRENT

**As of 2026-09-18: streaming evidence integration validated locally for source
publication.**

Objective: generic offline, traceable capture-to-protocol reconstruction; not automatic
intrusion detection or a claim to repair an external system without its captures.

Controlling contract: [`ENGINEERING.md`](ENGINEERING.md), criteria C01–C13.
Source identity and precise check times: `../evidence/local-validation.json`.
File identities: `../evidence/source-manifest.json`.
Package checks: `../evidence/delivery-check.json`.
These are evidence/navigation, not a production promotion decision.

State: the snapshot analyzer and bounded streaming analyzer are implemented. The
current local receipt records 135 root Rust selectors (133 collected on Windows),
40 streaming contract tests, 68 Python tests plus 23 subtests, passing debug/release
builds, formatting, warnings-denied Clippy, black-box CLI checks, the independent
93-case hardening CLI oracle, three semantic mutations, and both optional fuzz
workspace manifests compiling. This is synthetic local proof. No CI observation,
fuzz campaign, deployment, performance qualification, security audit, or
representative real-world capture replay has been provided.

Next action: keep the package and source manifest aligned with changes, then add
cross-platform CI observations, a POSIX fuzz worker with retained receipts, measured
workload/security qualification, and lawfully usable real-world mismatches if this
baseline is taken beyond local synthetic validation. Use the same fixture truth and
contract; do not weaken them to obtain a green result.

After that gate: compare one known-mismatching, lawfully usable real-world capture layer by
layer and record the first disagreement. Packet count, bytes and raw clocks precede
flow assignment, stream bytes, protocol messages, transactions and external labels.

Rollback: this source publication has no runtime mutation. Delete an exact disposable
build or local analysis output only under the owner's authority. Source captures are
never rewritten. Failed generic writer output must be discarded, not resumed blindly.
