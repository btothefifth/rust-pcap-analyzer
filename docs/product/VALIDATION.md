# Qualification plan and interpretation of receipts

## Current BGP qualification authority

[BGP_COMPLETION.md](BGP_COMPLETION.md) defines the active acceptance boundary and
[`bgp-support-matrix.json`](bgp-support-matrix.json) links every declared profile
area to owning code and tests. `tools/tests/test_bgp_support_matrix.py` checks the
matrix structure, complete profile coverage, unique IDs, valid states, and every
repository path on each row. Other implementations may be exercised as
differential disagreement probes, but only primary specifications plus
independent byte/state invariants adjudicate correctness.

The per-slice receipts below are chronological. When their worker limitations or
open-item lists conflict with later source and tests, use the dated audit-fix
receipt and [the current implementation pointer](../implementation/CURRENT.md);
never treat an earlier receipt as proof for a later source tree.

## Latest local BGP audit-fix receipt — 2026-09-25

The Windows Rust 1.85.1 checkout produced the following fresh evidence for the
current audit-fix source. The full product qualification receipt is
**BLOCKED, not failed**: every gate executable on this host passed, while three
platform/toolchain gates could not run.

- Product all-target debug and release suites: 447 passed in each profile.
- Root, streaming, product, and FFI formatting, locked debug/release tests,
  warnings-denied Clippy, and release builds passed. All six product feature
  profiles passed: no-default, standard, extensions, industrial,
  industrial-full, and binary.
- `scripts/validate.py` completed all 13 ordered steps: static and fixture
  checks, independent oracle checks, locked offline root check/debug/release/
  Clippy/build, CLI and hardening checks, and semantic mutation checks.
- The full `scripts/validate_product.py` run passed 198 Python tests (3
  skipped), the catalog audit, JavaScript model tests, and every Rust/profile
  gate listed above.
- `tools/tests/test_bgp_support_matrix.py` passed all 4 contract tests.

The receipt could not execute the C-header compile (`cc` unavailable), the
Linux-only injected live-denial check, or the Linux C-ABI link/run check. It
records sustained fuzzing, representative large-capture benchmarking, and full
browser-to-native exercise as NOT RUN, and normative protocol qualification as
NOT ESTABLISHED. These are open qualification gates, not product-test failures.
This remains local Windows evidence, not cross-platform qualification. Exact-
commit Linux/macOS execution, lawful real-corpus disagreement triage, measured
scale/performance, security review, and complete normative profile coverage
remain open. The product remains an offline analyzer: no collector authenticity,
endpoint negotiation, installed-route truth, or live network behavior is
established by these checks. See [the current implementation pointer](../implementation/CURRENT.md)
for the prioritized remaining work. Historical receipts below describe their
own source snapshots only.

## Windows status-endpoint race repair - local candidate

The first GitHub run for the preceding published tree exposed a concrete
Windows-only defect in the local evidence UI: while a worker was atomically
replacing its `state.json`, a status read could raise `PermissionError`. The
HTTP handler's broad permission mapping mislabeled this internal filesystem
condition as an authorization 403. The workflow log showed the failure in the
Windows Python contract job; it was not a protocol-parser or authorization
failure.

The current candidate retries only transient `PermissionError` from the
workspace-state read with a bounded 25-attempt linear backoff (4 ms per step).
Exhaustion becomes a redacted HTTP 503; token, Host, and Origin rejection remain
HTTP 403. Regression tests cover transient recovery through both the status and
job-list endpoints, bounded exhaustion and redaction, the real HTTP mapping,
preserved authorization denials, and normal worker query/export behavior.

Fresh Windows run `pcap-product-validation-20260925-native-05` completed with
202 Python tests passed and 3 skipped; catalog audit, JavaScript model tests,
all root/streaming/product/FFI formatting, debug/release tests, warnings-denied
Clippy, release builds, six product feature profiles, and all 13 ordered
baseline-validator steps passed. The receipt is still **BLOCKED** because this
host lacks `cc` for the C-header check and cannot run the Linux-only live-denial
and linked C-ABI checks. Sustained fuzzing, representative large-capture
benchmarking, full browser-to-native exercise, and normative protocol
qualification remain unrun or unestablished. Published candidate commit
`8ff367591d66045ea1a0172a5c0e516b88fe592e` then passed both exact-commit GitHub
Actions workflows: [native validation #62](https://github.com/btothefifth/rust-pcap-analyzer/actions/runs/36178305932)
and [streaming evidence contracts #58](https://github.com/btothefifth/rust-pcap-analyzer/actions/runs/36178305843).
All six Ubuntu, Windows, and macOS jobs passed, including the Windows contract
job that exposed this race. This records tested implementation-code evidence;
it does not change the unrun or unestablished product gates listed above.

## Captured BGP producer parity - source candidate

The captured producer extension in [BGP_PRODUCER.md](BGP_PRODUCER.md) stages
`decode_pcap` state until complete budget and output checks succeed. It binds
source/session/capture context, retains both OPEN directions and repeated
advertisements, exposes exact capability and path-attribute occurrences, and
uses the first ordinary path-attribute occurrence as the only semantic candidate
(subject to its own validation) while retaining later occurrences with explicit
discard dispositions. Repeated
MP_REACH_NLRI or MP_UNREACH_NLRI requires session reset. Repeated OPENs
no longer infer a new generation. A missing session produces unknown generation,
not another session's state. Negotiation and all authority claims remain false.

Imported normalizer bytes and import/state/replay partition, clock, checkpoint
and boundary contracts remain unchanged. The new occurrence value coordinates
are validated by state admission and excluded from state/association path
identity, while their evidence is retained. Captured output gains additive fields;
strict consumers and event hashes must account for the documented migration.

The worker did not execute Rust, but the integrator applied the direct patch in
an isolated Windows checkout and repaired one default-depth compatibility issue
and six Clippy test-fixture issues before acceptance. Fresh format, workspace
check/test/Clippy, product release test/Clippy, producer/replay/import/state/
association vectors, root validation and portable product validation all pass.
Linux/macOS runtime, live, scale, fuzz, secure, external-source verification,
adapter and normative qualification remain open. Review findings and exact
remaining boundaries are recorded in the producer contract and validation
receipt.

Focused commands after isolated canonical patch application:

```sh
python product/tests/bgp_producer_vectors.py -v
cargo test --manifest-path product/Cargo.toml --locked --offline --test bgp_producer
cargo test --manifest-path product/Cargo.toml --locked --offline --lib deep::bgp::
cargo test --manifest-path product/Cargo.toml --locked --offline --test bgp_state
cargo test --manifest-path product/Cargo.toml --locked --offline --test bgp_import
cargo test --manifest-path product/Cargo.toml --locked --offline --test bgp_replay
cargo test --manifest-path product/Cargo.toml --locked --offline --test bgp_association
cargo test --manifest-path product/Cargo.toml --locked --offline --test pcap_depth_cli
```

Then retain all root/product/streaming fmt/check/build/test/Clippy, release and
product feature gates below. No old PASS receipt qualifies this candidate.

## Generic normalized BGP replay — source candidate

The opt-in `deep::bgp_replay` API in [BGP_REPLAY.md](BGP_REPLAY.md) wraps existing contextual
imported observations in a bounded, ordered feed envelope. It reuses source,
batch/checkpoint, clock and generation metadata; exact replay is a no-op,
changed ordered records quarantine the feed, and boundaries remain explicit.
Pages are staged through the existing candidate reducer before receipt publication.

Replay and association receipts preserve provenance and coverage. Partial or
unknown feed coverage cannot be upgraded by a final marker or caller association
context. External-source verification and the caller's adapter remain outside
this I/O-free module. There is no new CLI/event integration, dependency, endpoint
RIB, best-path, reachability, attack, causality or source-authority claim.

The original worker did not run Rust. The integrated replay slice has since
passed its focused native and independent-vector gates on Windows. The commands
below remain the reproducible focused gate; cross-platform and adversarial
qualification is still separate.

Focused native commands for a complete isolated patched checkout:

```sh
python product/tests/bgp_replay_vectors.py -v
cargo test --manifest-path product/Cargo.toml --locked --offline --test bgp_replay
cargo test --manifest-path product/Cargo.toml --locked --offline --test bgp_import
cargo test --manifest-path product/Cargo.toml --locked --offline --test bgp_state
cargo test --manifest-path product/Cargo.toml --locked --offline --test bgp_association
cargo test --manifest-path product/Cargo.toml --locked --offline --test pcap_depth_cli
cargo fmt --manifest-path product/Cargo.toml --all -- --check
cargo check --manifest-path product/Cargo.toml --locked --offline --all-targets
cargo test --manifest-path product/Cargo.toml --locked --offline --all-targets
cargo test --manifest-path product/Cargo.toml --locked --offline --release --all-targets
cargo clippy --manifest-path product/Cargo.toml --locked --offline --all-targets --all-features -- -D warnings
cargo test --manifest-path product/Cargo.toml --locked --offline --no-default-features --test bgp_replay
```

Then retain root and streaming fmt/check/test/Clippy, product feature profiles and
all existing independent gates. The worker's exact command attempts and blocked
checks are in the returned `VALIDATION.md` and command receipts. Python arithmetic
checks are not Rust replay, source verification or end-to-end acceptance. Complete
Windows/Linux/macOS, live, scale, fuzz, security and normative proof remain open
for this new slice unless separately executed and recorded.

## Candidate evidence association — local Windows native acceptance

[BGP_ASSOCIATION.md](BGP_ASSOCIATION.md) adds 40 native test functions and fixed
prefix/time TSV vectors. The authoring worker executed eight independent Python
vector checks but had no Rust toolchain. The integrator applied the complete
patch in an isolated Windows checkout and ran the native association tests,
workspace/product format-check-test-Clippy gates, release product coverage,
root validator and portable product validator. Historical acceptance remains
separate evidence for the earlier producer/import/state slices.

The focused commands below remain useful for reproducing or narrowing the
acceptance evidence:

```sh
python product/tests/bgp_association_vectors.py -v
cargo test --manifest-path product/Cargo.toml --locked --offline --test bgp_association
cargo test --manifest-path product/Cargo.toml --locked --offline --test bgp_import
cargo test --manifest-path product/Cargo.toml --locked --offline --test bgp_state
cargo test --manifest-path product/Cargo.toml --locked --offline --lib deep::bgp::tests
cargo test --manifest-path product/Cargo.toml --locked --offline --test pcap_depth_cli
cargo fmt --manifest-path product/Cargo.toml --all -- --check
cargo check --manifest-path product/Cargo.toml --locked --offline --all-targets
cargo build --manifest-path product/Cargo.toml --locked --offline --all-targets
cargo test --manifest-path product/Cargo.toml --locked --offline --all-targets
cargo test --manifest-path product/Cargo.toml --locked --offline --release --all-targets
cargo clippy --manifest-path product/Cargo.toml --locked --offline --all-targets --all-features -- -D warnings
cargo test --manifest-path product/Cargo.toml --locked --offline --no-default-features --test bgp_association
```

The root and streaming fmt/check/test/Clippy and existing product feature,
release, CLI and projection matrices were also run for this local acceptance.
The Python vectors remain an independent arithmetic witness, not the native
oracle. Source ingestion/verification, production association, Linux/macOS
runtime, live, scale, fuzz, security and normative qualification for this
addition remain unproven unless a later receipt explicitly records them.

## Imported BGP context — local Windows native acceptance

The extension in [BGP_IMPORT.md](BGP_IMPORT.md) adds 33 native tests in
`product/tests/bgp_import.rs` and eight independent Python identity/transition
checks in `product/tests/bgp_import_vectors.py`. The native tests, the existing
BGP state/producer coverage, product release checks, workspace checks, release
Clippy and the root/product validation drivers passed in the complete local
Windows checkout. The worker host lacked Rust tooling, so its package receipt
is not native proof; the local receipt is the acceptance evidence for this
addition.

Required focused commands in a complete patched checkout:

```sh
python product/tests/bgp_import_vectors.py -v
python product/tests/bgp_state_vectors.py -v
cargo test --manifest-path product/Cargo.toml --locked --offline --test bgp_import
cargo test --manifest-path product/Cargo.toml --locked --offline --test bgp_state
cargo test --manifest-path product/Cargo.toml --locked --offline --lib deep::bgp::tests
cargo test --manifest-path product/Cargo.toml --locked --offline --test pcap_depth_cli
```

Then run the root/product/streaming fmt/check/test/clippy and product debug,
release and feature matrices below, including `--no-default-features` for the
new test target. The exact local commands and results are retained in the
validation receipt. Linux/macOS native execution, live, scale, fuzz,
external-corpus, secure and normative qualification remain open for this
extension; Windows acceptance does not establish those claims.

## BGP candidate route-state consumer — new source candidate

The separate API in [BGP_STATE.md](BGP_STATE.md) adds 31 Rust test functions and
five fixed synthetic wire vectors. The authoring worker lacked Rust tooling, but
the candidate was reviewed and executed in a complete isolated Windows checkout.
Formatting, product debug/release all-target tests, workspace check/test/clippy,
and the product validation gates passed locally for the reviewed tree. Earlier
Windows receipts below remain baseline history rather than evidence for this
candidate.

The independent fixture arithmetic test is
`python product/tests/bgp_state_vectors.py -v`; its six Python tests passed in
the worker and remain a separate wire-vector oracle. They validate fixed lengths,
byte values and ranges, not Rust state reduction.

Run in a complete, isolated checkout after applying and reviewing the patch:

```sh
cargo fmt --manifest-path product/Cargo.toml --all
cargo test --manifest-path product/Cargo.toml --locked --offline --test bgp_state
cargo test --manifest-path product/Cargo.toml --locked --offline --lib deep::bgp::tests
cargo test --manifest-path product/Cargo.toml --locked --offline --test pcap_depth_cli
cargo fmt --manifest-path product/Cargo.toml --all -- --check
cargo check --manifest-path product/Cargo.toml --locked --offline --all-targets
cargo test --manifest-path product/Cargo.toml --locked --offline --all-targets
cargo test --manifest-path product/Cargo.toml --locked --offline --release --all-targets
cargo clippy --manifest-path product/Cargo.toml --locked --offline --all-targets --all-features -- -D warnings
cargo test --manifest-path product/Cargo.toml --locked --offline --no-default-features --test bgp_state
cargo test --manifest-path streaming/Cargo.toml --locked --offline --all-targets
cargo test --manifest-path streaming/Cargo.toml --locked --offline --release --all-targets
cargo clippy --manifest-path streaming/Cargo.toml --locked --offline --all-targets --all-features -- -D warnings
cargo fmt --all -- --check
cargo check --locked --offline --all-targets
cargo test --locked --offline --all-targets
cargo clippy --locked --offline --all-targets --all-features -- -D warnings
```

Also retain the existing product feature matrices and independent protocol
qualification gates. Package/fixture arithmetic checks are not native reducer,
compiler, serialization or cross-platform proof. Linux/runtime, live, scale,
fuzz, external-corpus and normative gates are open for this candidate. The
review repaired producer digest labels, missing-direction state mutation,
attribute-local MP bounds, ordinary duplicate-attribute semantics, and repeated
MP attribute session-reset handling. Direct API budget parity and broader
capability/session semantics remain follow-up work in BGP_STATE.md.

## DNP3 fragment and streaming confirmation candidates — Windows native acceptance

Accepted root/streaming base: `d9f7c4fbb80c5355643b241fafb9c7687091a1b5`.
The root and streaming implementations maintain separate output seams; neither
changes the generic transaction path. See DNP3 workflow coverage for current
behavior and explicit limits.
The root slice provides `correlate::dnp3_confirmation_candidates`, a reusable
CRC-checked fragment witness verifier, and separate analysis/JSON fields
`dnp3_confirmation_candidates` and `dnp3_confirmation_error`. The streaming
slice adds a separate `dnp3.confirmation_candidate` event projection for
verified TCP fragments, bounded by capture/session/window/generation and exact
participant evidence. It does not replace or change `transaction_candidates`.

One verified CONFIRM and one eligible response fragment in a flow can produce
`candidate_confirmation` only with reversed individual addresses, opposite
captured directions and link DIR, equal fragment sequence and UNS namespace,
CONFIRM CON=0 and response CON=1. Reuse, duplicate confirmations/targets, colliding
header alternatives and unverifiable fragments never select a winner. A
transport-complete fragment need not belong to a complete application message;
this does not decode or complete its object body. Header bytes, source spans,
link CRC dependencies and all packet witnesses remain explicit.

**This worker has not executed Rust.** Cargo, rustc, rustfmt and Clippy were absent
in the Debian Linux worker. Native command attempts are BLOCKED, not PASS. The
38 new Rust tests are authored coverage only. Independent Python checks passed
for 33 fixed link vectors, 15 header-relation cases and an eight-packet capture's
lengths, CRCs, hashes, IPv4/TCP checksums, header offsets and timestamp integers.
Those checks do not execute the Rust verifier, grouping, JSON or CLI. See
[../DNP3_WORKFLOWS.md](../DNP3_WORKFLOWS.md) and the returned validation receipts.

The worker receipt is historical evidence of its unavailable Rust toolchain, but
the exact patched worktree has since passed fresh Windows native
format/build/test/release/Clippy gates plus product and streaming matrices. Linux
and macOS CI/runtime receipts are still open and must not be inferred from Windows.
Secure authentication,
endpoint acceptance/effects, causality and normative conformance are not claimed.
The streaming projection is TCP-only and does not pair separate UDP datagrams;
the generic transaction path remains untouched. Cross-platform CI/runtime
evidence, endpoint-authoritative cross-APDU file-transfer/reconciliation, Group 70 authentication and
secure file semantics, platform/live, scale, fuzz and external-corpus
qualification remain open.

The bounded Group 0 attribute slice has focused semantic evidence for typed
scalar envelopes, known boolean variations, hash-only values, extended lengths,
attribute-list entries, exact source spans, truncation, invalid widths and
header-only all-attributes requests. The bounded Group 70 slice adds focused
valid, truncated, and opaque-neighbor cases for free-format file-object
variations 3--8, exact object spans, full-width block numbers, descriptor metadata,
optional status text, status, and hash-only sensitive fields. The focused semantic suite is 60
passing tests on Windows; the full
repository and product gates below must be rerun after any
 further code or documentation change. This is not Linux/macOS qualification.

The bounded BGP depth slice adds seven focused unit cases and a real
`bgp.pcap` `pcap-depth` regression for normalized captured route evidence. It
also exposes the same generic normalized shape for caller-supplied imported
observations, while retaining provenance and explicitly refusing endpoint-state,
causality, best-path, RIB, timing, and cross-source-correlation claims. This is
a bounded evidence slice, not full BGP conformance or route-state reconstruction.

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
cargo test --manifest-path history/Cargo.toml --locked --offline --all-targets
cargo clippy --manifest-path history/Cargo.toml --locked --offline --all-targets -- -D warnings
cargo check --manifest-path history-app/Cargo.toml --locked --offline --all-targets
cargo clippy --manifest-path history-app/Cargo.toml --locked --offline --all-targets -- -D warnings
cargo test --manifest-path product/ffi/Cargo.toml --locked --offline --all-targets
python scripts/validate.py
```

The opt-in depth smoke path is:

    cargo test --manifest-path product/Cargo.toml --locked --offline --test pcap_depth_cli
    cargo run --manifest-path product/Cargo.toml --locked --offline --bin pcap-depth -- analyze product/tests/fixtures/opcua_tcp.pcap --workspace NEW_DIRECTORY --format ndjson
    cargo run --manifest-path history/Cargo.toml --locked --offline -- build history/fixtures/wrap.pcap HISTORY_DIRECTORY
    cargo run --manifest-path history-app/Cargo.toml --locked --offline -- CAPTURE HISTORY_DIRECTORY GENERATION_HEX DIRECTION PROTOCOL OUTPUT.ndjson
    python -m unittest tools.depth.test_opcua_crypto -v

The DNP3 CLI regression analyzes the shipped TCP capture and checks that both
assembled and per-fragment depth evidence are consumed. NEW_DIRECTORY and
OUTPUT.ndjson must not already exist. The depth smoke receipt is evidence of
source consumption and bounded output, not complete protocol or endpoint-history
qualification.

Retain the existing repository's streaming/independent-oracle/hardening gates. The
new fixture source and cases do not replace those. The current Windows integration
has passed the repository-wide Rust format, debug/release, build, feature-matrix
and warnings-denied Clippy checks with the pinned toolchain. Keep the explicit PATH
setup required by Rustup on machines where `cargo` is not on the inherited process
PATH. Never loosen expected truth or delete tests to get green.

## Latest local integration receipt

On 2026-09-21, the isolated patched worktree passed on Windows:

```text
cargo fmt --all -- --check
cargo test --locked --offline --all-targets
cargo test --locked --offline --release --all-targets
cargo build --locked --offline --release
cargo clippy --locked --offline --all-targets --all-features -- --deny warnings
cargo test --manifest-path product/Cargo.toml --locked --offline --all-targets
cargo test --manifest-path product/Cargo.toml --locked --offline --release --all-targets
cargo build --manifest-path product/Cargo.toml --locked --offline --release --all-targets
cargo test --manifest-path streaming/Cargo.toml --locked --offline --all-targets
cargo test --manifest-path streaming/Cargo.toml --locked --offline --release --all-targets
cargo clippy --manifest-path streaming/Cargo.toml --locked --offline --all-targets --all-features -- --deny warnings
cargo build --manifest-path streaming/Cargo.toml --locked --offline --release
python -B scripts/validate.py
python -B scripts/validate_product.py --portable-only --output evidence/product-validation-streaming
```

The root suite including 38 confirmation tests passed. The streaming suite passed
8 unit tests, 40 contract tests and 7 semantic-pipeline tests in both debug and
release; warnings-denied Clippy passed for root, product and streaming. The root
qualification driver and portable product qualification also passed; the latter
ran the 191-test Python suite, catalog audit and JavaScript model tests. This is
Windows evidence only. Linux/macOS CI, live capture, sustained fuzz, large-scale,
and normative gates remain open. The generated receipt directories are local
evidence and are not a substitute for cross-platform runner results.

## Earlier local baseline receipt

On 2026-09-20, the clean Windows checkout at the roadmap base commit passed this
expanded debug qualification set:

```text
cargo fmt -- --check
cargo build --all-targets
cargo test --all-targets
cargo clippy --all-targets --all-features -- --deny warnings
cargo test --manifest-path product/Cargo.toml --all-targets
cargo test --manifest-path streaming/Cargo.toml --all-targets
cargo test --manifest-path history/Cargo.toml --all-targets
cargo test --manifest-path history-app/Cargo.toml --all-targets
```

The root suite reported 184 passing tests, the product suite 52, streaming 46,
and history 24; `history-app` compiled and its test targets completed without
failures. These are fresh Windows debug receipts for the existing baseline. They
do not close release, Linux, live-NIC, sustained-fuzz, 50--500 GiB scale,
cross-platform FFI, or normative protocol gates, and they do not prove the
roadmap's full DNP3 objective. The root receipt includes the bounded DNP3
semantic expansion for indexed reads, one/two/four-byte ranges, extended
qualifier prefixes, standard object/deadband/variable-octet layouts, named
function codes, primary/secondary link-control fields, broadcast evidence,
message-level semantic reports, and CROB evidence.

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
