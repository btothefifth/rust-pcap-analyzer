# Follow-up qualification and continuation

## Bounded BGP corpus and semantic comparison

This is the implemented follow-on to merged PR #1, rebased onto cleanup PR #3.
The bounded results and remaining coverage gaps are recorded below. The baseline's finite
samples and gate results remain in
[`pr-followup-validation.json`](../../evidence/pr-followup-validation.json).

| Increment | Acceptance evidence | Current state |
|---|---|---|
| Source diversity | Public RIB and UPDATE samples spanning at least two collectors, two UTC dates, and IPv4/IPv6; record admitted bytes and any missing profile cells | Executed; see bounded results below |
| Independent comparison | Independently produced normalized data with pinned producer/adapter versions; compare existing per-field route actions/prefixes, then path/attribute fields only where both sides declare comparable coverage | Executed; see bounded results below |
| Disagreement regression | Preserve the first divergence, exact source anchors and both interpretations through existing bundles; adjudicate a confirmed defect against bytes/specification and retain a small synthetic regression | Executed; see bounded results below |

Each sample needs its URL, retrieval time, exact admitted digest/length,
checkpoint identity, decoder/configuration, coverage/dispositions, and output
digests. A partial HTTP/gzip prefix must retain missing parent digest and trailer
verification as unknown. A missing-OPEN quarantine or unsupported family remains
visible; it does not become successful route-semantic coverage. Sources replay
independently across checkpoints.

Use the existing [stream evidence and comparison contract](BGP_STREAM_EVIDENCE.md).
An external implementation supplies a disagreement probe, not an oracle by
consensus. Start with the v2 action/prefix fields already implemented. Any broader
field needs an explicit availability contract and independently expected cases
before comparison can claim agreement. Record comparable and unavailable fields
separately, and verify the full export even when a bounded row partition is used.

Keep public input bytes and generated reports in ignored local storage; commit
source manifests, recipes and synthetic regression fixtures. For the initial
matrix, cap each acquired compressed fragment at 2 MiB, each expanded source at
16 MiB, and all owned scratch at 256 MiB including input/output coexistence.
Use smaller sources/partitions when existing tool limits refuse admission;
preserve the failed attempt and state the narrowed comparison scope.

Before each acquisition or replay, account for all project storage and peak
coexistence under [AGENTS.md](../../AGENTS.md). Serialize costly commands with
one Cargo/test worker, a verified 2 GiB memory cap and no swap; retain bounded
commands, wall-time and process-tree memory observations. These finite samples
do not establish a stable throughput or aggregate RSS qualification.

Performance optimization, sustained fuzzing, full normative qualification and
caller-clocked GR/LLGR assessment remain separately scoped work. This increment
extends the evidence matrix through existing owners; it adds no protocol-state
or live-input feature.

## PR #2 implementation plan (2026-11-09)

The implementation base is cleanup merge
`fabca5c961c09c9d14ba0cbf7df35a045965e278`. The branch was rebased from
`c16c5f4d03cf66f8e5df2ce77388cd38a6ff1b0a`; the original planning commit is
preserved in Git history. This section owns current acceptance and progress.
The [PR review](https://github.com/btothefifth/rust-pcap-analyzer/pull/2#issuecomment-6276112244)
adds eight existing-code defects to the corpus work. All eight repairs and the
Telnet selectivity change are implemented with passing focused regressions.

Required outcomes are faithful source-bound interpretation, isolation between
sessions/devices, useful observations within the advertised bounds, and an
independently reproducible comparison. Malformed evidence must stay inspectable
without acquiring complete semantic identity. Valid neighboring records and
independent sessions must continue. This remains offline research: no live
routing, endpoint truth, new timer state machine, or broad conformance claim.

### Ordered implementation and proof

| Step and owner | Change and preserved behavior | Acceptance at the consumer |
|---|---|---|
| 1. Shared BGP values (`deep/bgp.rs`, `bgp_mrt.rs`) | Reuse AS0 and IPv4 next-hop checks for TABLE_DUMP_V2; preserve raw malformed attributes and valid sibling entries | `bgp_mrt` tests for AS0/multicast and valid adjacent entries; sealed and streaming replay agree on incomplete identity |
| 2. Imported FSM (`deep/bgp/mrt.rs`) | Accept Connect/Active to OpenConfirm; preserve OPEN context and generation; retain rejection of direct jumps to Established | `bgp_mrt_bgp4mp_replay` exercises bilateral OPEN, sender KEEPALIVE ordering, each legal edge, Established and UPDATE through fresh replay |
| 3. Attribute projection (`deep/bgp.rs`, `bgp/mrt.rs`, `bgp/bmp.rs`) | One accepted-occurrence helper implements first-occurrence duplicate policy; discarded ATOMIC_AGGREGATE is false | BMP and BGP4MP import/replay cover absent, valid, malformed, malformed-first and valid-first duplicates, including retained occurrence dispositions |
| 4. Captured replay (`deep/bgp_store.rs`) | Keep a tainted session quarantined without invoking a forbidden gap mutation; do not hide other errors | `bgp_persisted_evidence` adds a post-conflict message and negotiated sibling route; fresh replay succeeds with the rejection and sibling evidence; corruption/budget tests stay fatal |
| 5. BACnet identity (`deep/bacnet.rs`, depth sink) | Include SNET/SADR, DNET/DADR and forwarded origin in assembly identity; retain transport generation/direction and explicit cuts | Separate logical devices cannot complete each other's segments; equal identities do complete. Exercise every address component and forwarded origin through Session and sink with packet witnesses |
| 6. Framing (`registry.rs`) | Drain with a cursor and compact once; charge consumed bytes on success and attempted bytes on incomplete/error paths | 2,000 KEEPALIVEs in one/split input produce exact offsets/spans, plus it-full TCP/179 integration. Deliberately low work still refuses; partial and malformed tails retain diagnostics |
| 7. IMAP (`protocols/it.rs`) | Select the third token for numeric untagged replies; preserve tagged and keyword replies and actual verb spans | EXISTS/EXPUNGE/FETCH, invalid/missing verbs, and greeting + EXISTS + tagged completion through framing |
| 8. SIP (`protocols/it.rs`) | Trim only allowed pre-colon SP/HTAB, validate header-name token, retain compact/case handling | Long/compact space/tab forms pass; contradictory duplicate lengths fail; folding remains unsupported |
| 9. Selectivity and availability | Require Telnet command/negotiation evidence for initial detection while preserving escaped IAC in established streams. Trace ASN selector availability independently of whole identity before changing its contract | BGP/Telnet coexistence and valid Telnet tests. Any ASN change must prove validated path, AS4 reconstruction, opaque unrelated attributes and malformed/ambiguous/context-missing paths through persisted query |
| 10. Corpus research (`tools/research/bgp_compare.py`, existing bundle owner) | Keep acquisition separate from offline comparison; pin an independent MRT decoder and a narrow adapter, using existing normalized v2 envelopes | Two collectors and two dates with RIB/UPDATE and observed IPv4/IPv6 or explicit missing cells; compare action/prefix availability, verify complete exports, retain source/range and first-divergence bundles |

Each defect gets a failing regression on the rebased baseline before repair,
then the positive and preserved cases run against the repaired owner. Reuse
existing fixtures and public import/replay entrypoints. Full protocol adapters
are not interchangeable: snapshots remain collector evidence, missing OPENs
remain quarantined, and BMP policy streams retain their scope.

### Corpus execution contract

Use RIPE RIS rrc00 and rrc01, initially 2026-10-01 and 2026-10-02 UTC, selecting
bounded bview and update fragments. Confirm source availability before fetching.
Retain complete MRT records from bounded decompression, including each RIB's
peer table; do not fabricate session context. If a prefix misses IPv6, select
complete IPv6 records within the same bounded expanded fragment or explicitly
record the missing cell. Never splice records across checkpoints.

The independent decoder candidate is upstream `t2mune/mrtparse`; pin the exact
release/source hash and inspect its Reader interface before use. It is optional
research tooling, never a Rust runtime dependency. Keep its raw interpretation
separate from native outputs. The adapter maps only independently decoded
source offsets, record/entry ordinals, route actions and prefixes; unavailable
or unsupported fields remain in the denominator. Validate it with hand-encoded
known answers before public samples. RFC/byte adjudication resolves disagreement;
matching implementations alone do not prove correctness.

Retain in a committed manifest: source URLs, retrieval clocks, admitted compressed
and expanded byte counts/digests, truncation/trailer status, exact decoder and
adapter identity, commands/configuration, checkpoint/source identities, coverage,
comparison counts, output hashes and adjudicated divergences. Public bytes,
exports and bundles live under ignored `.local-build/pr2/`. Synthetic witnesses
and reproducible recipes are committed. Reproduction never executes a command
embedded in an input artifact. Bound output and all scratch to 256 MiB; use
explicit row partitions and smaller record selections when necessary.

### Plan review dispositions

Independent plan review of `31bd751` plus plan SHA-256
`29b8caa8f9c6f629506c978bdef0e646b7879186542f3ee7cc47052abc893edd`
identified three refinements, accepted before implementation:

- Outgoing KEEPALIVE may precede OpenConfirm in states 2/3/4 when valid
  bilateral OPEN context is present. Incoming controls and missing/conflicting
  context remain quarantined there. Exercise both directions and fresh replay.
- BACnet assembly keys use bounded, unambiguous address identity. The existing
  broad `cut` retires every logical address under its exact transport/transaction
  scope; an address-specific cut can retire one chain while preserving siblings.
  Test both cuts and reuse, including maximum address lengths.
- Public qualification requires nonzero comparable action and prefix rows for
  each claimed family. Missing required family evidence blocks that claim;
  missing OPEN UPDATE rows remain coverage evidence, never semantic parity.
  Independently constructed negotiated witnesses qualify UPDATE semantics.
  External syntactic acceptance does not claim native session admission, so
  disposition coverage is unknown unless both producers assess the same fact.

### Resource and completion gates

Before this phase the checkout occupied 23,643,557,401 bytes; the task-installed
Rust toolchain adds 545,418,894 bytes. Reuse existing build output. Allow at most
8 GiB additional build output and 256 MiB research scratch, stopping growth
before 40 GB total. This leaves headroom below the owner's strict 50 GB ceiling.
A systemd user service probe read back `memory.max=2147483648` and
`memory.swap.max=0`. Run costly commands in that containment with an explicit
wall deadline, one Cargo build worker and one Rust test worker. Retain exit,
wall and cgroup memory-peak observations. No concurrent source mutation during
a proof or independent review.

Run focused Rust suites first, then product formatting and strict Clippy, the
product feature/workspace gates, root validation and affected Python research
suites against the stabilized candidate. Preserve prior failed attempts and
classify fixture, environment and product failures separately. Existing cleanup
results are historical, not proof of this candidate. Review-loop starts with an
independent plan/source review and ends only after a fresh full branch-and-plan
review has no actionable in-scope finding. Record exact reviewed generations,
findings, repairs, executed selectors and limits here. Publish with an expected
remote-head lease, link PR #2, update its description and mark it ready only when
the implemented scope and evidence support that status. Hosted CI is a separate
gate. Rollback is a branch repair or revert; no deployed system is changed.

### Bounded execution results

[`pr2-corpus-validation.json`](../../evidence/pr2-corpus-validation.json) records
all eight public acquisitions, exact input/output hashes, native command arguments,
coverage, decoder pin, synthetic results and the adjudicated defect witness.
The native binary and reviewed source are bound separately; generated public
bytes and bundles remain under ignored `.local-build/pr2/`.

- RIPE RIS rrc00 and rrc01, October 1 and 2, 2026: four RIB and four UPDATE
  prefixes, each acquired with a 256 KiB compressed and 2 MiB expanded cap.
  Selection retains the first peer table plus two RIB records, or 32 complete
  UPDATE-container records. The admitted derived sources are only a few KiB.
- Public comparison: 316 agreeing action/prefix fields, zero observed
  disagreements, and 4,146 unavailable field comparisons. The comparable RIB
  rows are IPv4. Public UPDATEs lack bilateral OPEN context and contribute no
  route-semantic agreement. IPv6 appears in three external UPDATE samples;
  it remains unavailable natively. No public IPv6 RIB parity is claimed.
- Independently authored known bytes: IPv4 RIB and negotiated IPv4/IPv6 UPDATE
  actions/prefixes agree with pinned mrtparse 2.2.0 and literal expected prefixes.
  Native IPv6 RIB MP_REACH remains unsupported and is explicitly asserted as
  unavailable. The fixture is `tools/research/fixtures/bgp-corpus-known.json`.
- The malformed `40 06 01 00` ATOMIC_AGGREGATE witness was executed with a
  clean baseline build at `31bd7510de3d6742b39f6bb932b5c7c962d47042` and the repaired
  binary. The baseline incorrectly projects true; the repair projects false.
  RFC 7606 section 7.6 and the exact attribute bytes determine the expected value.
  The verified first-divergence bundle retains the source range, both competing
  interpretations and both native exports. Its generic bundle verdict remains
  UNRESOLVED; the separate adjudication records the confirmed repaired defect.

Focused native evidence includes all affected BGP suites, BACnet Session and
sink integration, framing (one batch, actual split pushes, profile detection,
work refusal and invalid tails), IMAP and SIP. Additional sealed replay tests
preserve malformed RIB evidence and valid neighbors; DelayOpen tests assert
unchanged generation and reject absent, unilateral or conflicting context.
The captured replay test checks the retained rejection and active sibling route.
Initial targeted runs failed on the eight baseline defects, then passed after
repair. Test-harness compile/configuration mistakes were corrected separately.
The latest supplemental run passed 39 BGP4MP and four framing tests; the captured
suite passed all 12 cases. The complete stabilized-candidate gates below include
strict Clippy and all of these final test assertions.

The final matrix run, including the malformed-MP regression, completed under
the verified 2 GiB/no-swap service. Its wall-time and cgroup peak are recorded
in the corpus receipt. Acquisition and earlier
attempts are separate receipts. These are finite run observations, not a
throughput, RSS or large-corpus qualification.

ASN selector availability was traced through `bgp_evidence::asn_route_match` and
its persisted-query callers. Its current contract requires complete route
identity. This PR preserves that conservative rule. Broader per-field ASN
selection is a future BGP contract increment, owned by the evidence and persisted
query surfaces: it must add one validated path-availability carrier through
captured, MRT and BMP producers, AS4 reconstruction and fresh replay before
relaxing selectors. Opaque unrelated attributes, malformed paths and missing
context must have distinct independent witnesses. A projection-only relaxation
would treat unqualified paths as selector evidence.

### Reproduction

Use a NEW output parent, the declared Rust toolchain, the pinned wheel from the
receipt, and the resource limits above. No research command installs dependencies.
Run the repository's existing product build, then acquire each matrix cell with
`python3 -m tools.research.bgp_corpus NEW_DIR --collector rrc00 --date 20261001 --kind bview`,
substituting each of the two declared collectors/dates and `bview`/`updates`.
The acquisition receipt records retained original expanded ranges; offsets in
`source.mrt` belong to that derived source. Parent hashes and gzip trailer
verification remain unknown for these prefixes.

```sh
cargo build --manifest-path product/Cargo.toml --locked --offline --bin pcap-depth
python3 -m tools.research.qualify_bgp_sample SOURCE.mrt NEW_RESULT_DIR \
  --binary target/debug/pcap-depth --wheel /path/to/mrtparse-2.2.0.whl
python3 -m tools.research verify-bundle NEW_RESULT_DIR/comparison.zip
python3 -m unittest tools.tests.test_mrtparse_adapter -v
```

Write the fixture's `hex` bytes to a new local file and run the same qualifier
for each synthetic case. Known prefix/availability answers are checked inside
the qualifier, independently of public agreement. For the atomic witness, retain
separate baseline and candidate `native.json` outputs, then run:

```sh
python3 -m tools.research.atomic_aggregate_witness ATOMIC_SOURCE.mrt \
  BASELINE/native.json CANDIDATE/native.json NEW_ADJUDICATION_DIR
```

For a fresh clone, build the publicly reachable baseline
`fabca5c961c09c9d14ba0cbf7df35a045965e278`. The recorded local build at `31bd751`
differs from that commit only in this plan and CURRENT.md; all native sources,
manifests and compiled includes are identical. The actual historical build
identity remains in the receipt; never substitute a stale binary of unknown
provenance. Acquisition, native replay and comparison are
separate operations. A failure retains its command log and does not qualify
that sample. Every comparison verifies its complete native export before taking
at most the first 64 rows. Reruns use new output directories; storage retirement
stays with the operator's existing scratch ownership rule.

### Review and integrated validation status

One independent plan round is complete with its three findings incorporated.
Implementation round 1 reviewed all 28 changed paths and their consumers against
`.git/pr2-review-implementation-1.json` (SHA-256
`b558f9a9ac8b745432e454bceaa6afdc19e1affaaa82f24c76be36bbaf39ee19`). It found two
issues, both addressed: missing family/NLRI fields from the pinned decoder now
retain an unavailable observation instead of crashing, and baseline reproduction
now uses the reachable main commit with verified native-code parity. The exact
75-byte malformed MP_REACH case failed with the original adapter; the repair
retains it and preserves the following valid UPDATE. A new synthetic fixture
and direct decoder-shape tests retain that regression.

The first complete-gate attempt stopped because its systemd environment omitted
Node from PATH. Correcting PATH made the package preflight pass. The retry passed
portable, root and streaming gates, then was intentionally interrupted before
repairing the review finding. A later run reached the aggregate 20-minute launcher
deadline without a reported product failure; its cached rerun used a 40-minute
aggregate bound with unchanged individual gate deadlines and memory limits.

Fresh implementation round 2 completed a full pass over the 28 changed paths,
752 source-frontier paths, controlling plan and actual consumers, with no remaining
actionable finding. Its frozen manifest SHA-256 is
`0bf792dae3eb340cf2b01870e1d95f0cc0fcfaa231dacd850bf88853d3046ade`.
The reviewer independently checked the retained source/output hashes, decoder
regression, corpus counts, atomic bundle and reachable-baseline code parity.

On that unchanged source, `scripts/validate_product.py` passed all 56 gates and
`scripts/validate.py` passed all 16 gates. Both receipts confirm unchanged source.
The product run completed in 6 minutes 50 seconds and root validation in 10.5
seconds under the declared containment. The committed corpus receipt records
gate commands, results, receipt hashes, review identity and exclusions. Final
status and receipt additions postdate those checks and change no executable
source or code-driving contract. No hosted-CI, publication or merge result is
claimed by this local validation record.

## Ordinary integrated gates

Run from a checkout with this candidate applied. All output paths below are NEW
paths under a trusted existing parent. Do not install or fetch dependencies from a
validation script. Prepare toolchains separately through the operator's trusted process.

```sh
cargo fmt --manifest-path history/Cargo.toml --all
cargo fmt --manifest-path product/Cargo.toml --all
python scripts/validate_followup.py --output /new/followup-validation
python scripts/validate_product.py --output /new/product-validation
python scripts/validate.py
python -m unittest discover -s tools/tests -v
node --test desktop/web/model.test.mjs
python -m tools.research audit
```

The follow-up driver records root/streaming/product/FFI/history format, debug,
release and warnings-denied Clippy checks separately. Run the existing product
feature matrix too; its scope is not replaced by the new driver. The driver exits
2/BLOCKED when required tools are unavailable and 1/FAIL on real failures. NOT_RUN
classes are explicitly listed, not converted into success.

Both repeatable drivers now require `native-semantic-cases` after the root
all-target release build. They resolve `examples/semantic_probe` from the actual
Cargo target directory, including `CARGO_TARGET_DIR`, and retain the case runner's
18-case receipt beside the gate logs. The ordered root validator also builds all
targets and runs the independent case gate with its debug artifact. Portable
semantic tool tests and product NDJSON/TLV parity each retain their own scope;
neither substitutes for execution of the independent native field/witness cases.

The shared subprocess owner drains both pipes under one aggregate byte budget
and checks the terminal output condition before a zero exit can become PASS.
Trusted POSIX children run in a new session. Timeout, output overflow,
interruption, partial pipe-reader startup failure, and ordinary completion all
stop the owned process group and reap the direct child before returning.
Nested runners inherit the exact outer group ID through a small exec shim and
keep their children inside that group; their local cleanup reaps the direct child
while the outer owner retains final descendant cleanup. This prevents a nested
semantic/research runner from escaping a timed-out qualification driver. Detached
children that deliberately create a new session remain outside this lifecycle
contract; it is not an OS sandbox. Qualification logs are capped at 64 MiB per
attempt, and timeout/interruption rows retain their logs and adverse status.
Windows tree termination uses `taskkill`; an unconfirmed stop is adverse and
does not supply POSIX containment proof. Linux execution cannot qualify Windows
or macOS cleanup behavior.

The cheap regression owner is `python scripts/test_owned_process.py -v`. Its
fixtures use tiny Python parent/child sleepers and at most 4 KiB burst output to
exercise terminal caps, two-stream accounting, interruption and partial startup
cleanup, recursive fuzz source membership, and source drift before a campaign
can claim PASS. The fixture tests execute no Rust or fuzz campaigns.

The integrated Windows run on 2026-09-19 recorded 26 required PASS gates,
including the real linked C ABI harness after preparing the x64 MSVC developer
environment. Six independent classes (browser-to-native, sustained fuzz, 50-500 GiB scale,
normative review, install/upgrade/uninstall and authorized NIC capture) remain
NOT_RUN in that driver. The baseline validator and the full product qualification
matrix also passed their portable/native Rust checks. A separate direct browser
smoke run passed with real requests, native-worker source binding and keyboard
navigation; it is not a substitute for the broader packaging/accessibility gate.

## Tier-A semantic evidence

The current integration includes a bounded semantic slice rather than a claim of
complete protocol support. Run its independent native and projection checks with
fresh output paths:

```sh
python scripts/test_semantic_tools.py -v
cargo build --locked --offline --example semantic_probe
python scripts/semantic_case_runner.py \
  --probe target/debug/examples/semantic_probe \
  --output /new/native-semantic-cases.json
python scripts/validate_semantic_product.py \
  --binary product/target/debug/pcap-product \
  --output-dir /new/semantic-product-parity
```

The completed Windows receipt contains 18/18 native semantic cases and complete
NDJSON/TLV event-sequence parity for five semantic captures. It covers DNP3
per-fragment object selection and Modbus bit/register semantics through the root,
streaming and product projections. It does not prove normative conformance,
cross-fragment DNP3 joining, complete application protocols or large-capture
performance. The semantic fuzz target builds with the approved local Rust nightly
and `cargo-fuzz 0.12.0` (`cargo +nightly fuzz build semantics`) and passes
warnings-denied Clippy. Windows `cargo test` for libFuzzer bins is not the fuzz
runner; use `cargo-fuzz`. No sustained fuzz campaign is claimed.

## Native history / independent witness validation

For every `history/fixtures/*.pcap`, build a NEW history and a NEW replay using
`pcap-history`, then run `python -m tools.history_native SOURCE HISTORY`.
Use hot-tuples=1, sort-entries=2 and frequent checkpoints on the interleaving case
to force eviction and multi-pass sorting. Confirm late conflicts expose alternatives,
not merged invented bytes. Test source mutation, damaged caches/journals/indexes,
quota exhaustion, cancellation and explicit torn-tail recovery. A native helper
must reproduce decisions exactly; the Python verifier does not adjudicate TCP policy.

`history/tests/` and CLI tests cover these contracts; their existence is not a pass.
Record actual compiler, binary/source hashes, commands and results. Force multi-wrap
traffic under both strict and explicitly assumed nearest-frontier policies. Report
unassigned/ambiguous placements and application coverage, not merely packet counts.

## C ABI link and execution

```sh
cargo build --manifest-path product/ffi/Cargo.toml --locked --offline
python scripts/check_linked_abi.py --output /new/linked-abi
```

On Windows use the prepared MSVC developer environment, or pass an explicit compatible
`--compiler` and `--library` import library. On POSIX the real shared library is linked
with a local rpath. No mock implementation is permitted. The C source checks caller
allocation/ownership, limits, exact output, stale handles and concurrency; it cannot
validate arbitrary non-null pointers or establish immunity to allocation aborts.

For the current Windows toolchain, the explicit form is:

```bat
call "%ProgramFiles(x86)%\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
cargo build --manifest-path product/ffi/Cargo.toml --locked --offline
python scripts/check_linked_abi.py --compiler cl.exe --library product\ffi\target\debug\pcap_evidence_ffi.lib --output C:\Temp\pcap-linked-abi
```

The Windows harness link includes `ws2_32`, `userenv` and `ntdll`, which are
required by the Rust standard-library symbols used by this FFI artifact. The
current Windows receipt passes link and execution; this does not qualify Linux
or other calling conventions.

## Actual browser-to-native gate

```sh
cargo build --manifest-path product/Cargo.toml --locked --offline
python scripts/check_browser_native.py --engine /path/to/pcap-product --output /new/browser-native
```

Use the actual binary name declared in the product manifest. Installed Playwright
and Chromium are optional test dependencies, never shipped core dependencies.
The script starts the real local server, clicks the real UI, waits for the native
worker, validates the source binding, navigates packet rows by keyboard and opens
the checked source-byte inspector. It does not mock requests or fall back to the
Python container mode. Policy-blocked loopback/browser absence is BLOCKED; application
or engine failures are FAIL. A screenshot alone is not this gate. Packaging, upgrades,
uninstall, file associations, signing and full accessibility remain separate.

## Research artifact compatibility

New comparisons emit research-differential.v2. Existing v1 report reproduction is
preserved exactly for old bundles. Do not rewrite stored v1 reports under v2 and
call their hash drift corruption. Missing prior fields/current-layer partial coverage
blocks the stronger earliest-prefix claim. Arrays and competing interpretations
remain ordered evidence. Rehashed false raw witnesses must still fail verification.

## Still-open engineering, in dependency order

1. Review the completed native checks and repair this candidate before broadening
   it. Review the history generation policy against RFC 9293 sections 3.4/3.6,
   RFC 1982 and adversarial
   endpoint captures. These sources describe serial/transport principles; the
   nearest-frontier research policy is not an RFC conformance claim.
2. Add disk-backed IP-fragment state and complete application-parser continuation
   driven by journal intervals. Explicitly propagate generation/epoch alternatives,
   FIN conflicts and gaps; never concatenate across ambiguity to satisfy a decoder.
3. Add efficient checkpoint resume only with independently verified state/journal
   commitments. Current recovery intentionally replays source prefixes.
4. Extend high-value DNP3 objects beyond the current per-fragment slice, then add
   BACnet segmentation, connected CIP and MMS session/presentation subsets with
   primary normative fixtures. Do not inflate the support table or equate labeled
   capture folders with decoded semantics.
5. Measure progressively larger same-policy workloads: few/many tuples, long streams,
   wrap/reuse/delay, fragments/tunnels, small/large frames, gaps/conflicts, NDJSON/TLV,
   history queries/replay and output/index amplification. Retain named hardware,
   warmup/repetition variation, process-tree RSS, logical/allocated disk peaks and
   coverage losses. This candidate has no 50–500 GiB or packet-rate pass.
6. Run sustained native fuzz/sanitizer campaigns and independent analyzer adapters,
   minimize findings, adjudicate against specifications/bytes/state, and retain each
   confirmed defect as a regression. No tool votes establish correctness.
7. Qualify linked ABI and actual authorized Linux NIC acquisition separately. Do not
   promote injected privilege failure to successful live capture. Keep Windows
   descendant containment and OS packaging/security review explicit.

Primary references: https://www.rfc-editor.org/rfc/rfc9293.html and
https://www.rfc-editor.org/rfc/rfc1982.html . These are research/specification sources,
not third-party runtime parsing dependencies.
