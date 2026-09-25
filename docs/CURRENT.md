# Repository baseline snapshot

**Baseline evidence date: 2026-09-20.** This page records the streaming and
opt-in depth/history snapshot validated on that date; it is not the current
release pointer. Current code status is maintained in
[`docs/implementation/CURRENT.md`](implementation/CURRENT.md), and the newer
BGP/DNP3 local audit-fix receipts are in
[`docs/product/VALIDATION.md`](product/VALIDATION.md).

Objective: generic offline, traceable capture-to-protocol reconstruction; not automatic
intrusion detection or a claim to repair an external system without its captures.
The opt-in depth contract is documented in docs/product/DEPTH_CONTRACT.md. It
adds bounded, source-bound protocol subsets and a sealed-history consumer without
changing the default parser or claiming complete endpoint replay.

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
