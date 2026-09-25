# Follow-up implementation status

This page preserves chronological implementation receipts. Statements below
that say a worker could not run Rust or list issues as still open are
point-in-time findings, not the current backlog. Use
[the current implementation pointer](../implementation/CURRENT.md) and the
[BGP completion contract](BGP_COMPLETION.md) for current status; the later audit
fix records duplicate-attribute and producer-boundary changes validated on
2026-09-25.

## Captured BGP producer parity — source candidate

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

This addition is not covered by the earlier Windows receipts below. Its native
Rust and complete-checkout acceptance checks remain unrun in the worker; the
returned validation record distinguishes Python vectors, source/patch checks and
blocked native commands. Existing BGP/DNP3 behavior is preserved.

Review findings: the existing contracts intentionally lack feed order/cursor/
completion semantics, use caller-wide association coverage, and can validate a
current-generation boundary before classifying a changed old record. The wrapper
supplies the missing contract, conservatively lowers coverage and quarantines
changed historical ordinals before state application. Source verification,
producer budget/staging/direction/capability issues and automatic integration
remain open. It is not a clean review or a full BGP qualification.

## Generic candidate evidence association — local Windows native gates pass

The separate `deep::bgp_association` module is specified in
[BGP_ASSOCIATION.md](BGP_ASSOCIATION.md). It retains normalized BGP/state witnesses
and independently shaped internal records under an explicit comparison policy.
Namespace and required dimensions, uncertainty windows, duplicate identities,
changed-content conflicts, alternative paths, unsupported dimensions and all
resource failures are explicit. Source batches/checkpoints are never merged.
Existing producer/reducer/DNP3/streaming code and output contracts are unchanged.

The review was not clean. The new boundary rejects whitespace-only identities
and positive authority/attack claims, preserves inactive/quarantined state
witnesses, and refuses silent clock overrides or missing import context. At that
acceptance point it did not repair the captured-producer budget/state-staging/
direction gaps, capability adjudication, duplicate scalar semantics, source
authentication or automatic sink boundary forwarding. Later producer work
repaired the direct budget/state-staging gaps and duplicate-attribute
dispositions; remaining capability, provenance/authentication and sink-boundary
limitations are tracked in the current pointer and completion plan.

The worker authored 40 native tests but could not execute Rust. The integrator
applied the complete patch in an isolated checkout and ran those tests, the
workspace/product format-check-test-Clippy gates, release product coverage,
root and portable validators, and the independent Python vectors successfully.
Linux/macOS runtime, live, scale, fuzz, security and normative gates remain
open. Earlier acceptance records below are historical, not this slice's proof.

## Imported BGP context — bounded source candidate

The typed opt-in API in [BGP_IMPORT.md](BGP_IMPORT.md) adds schema/version and
clock labels, immutable batch/hash/checkpoint identity, explicit generation
boundaries and bounded source-relative provenance. The candidate reducer keeps
partitions separate, rejects inconsistent transitions atomically, and preserves
replay/conflict distinctions without source preference or causal claims.
Legacy normalization keeps its API but now emits explicit null context/generation.
Captured normalized envelopes gain only the additive null context fields.

The accepted-integration review was not clean: this slice repairs the missing
import-context/batch-isolation seam and bounds legacy imported normalization.
Captured direct-API budget parity, captured metadata direction validation,
transactional decoder-state staging, broader capability semantics, duplicate
scalar projections and automatic sink boundary forwarding were the open items
at that acceptance point. Later work closes direct producer budgeting/staging
and the duplicate-attribute behavior; broader capability semantics, captured
direction validation and automatic sink boundary forwarding remain open. The
33 new native tests and eight independent Python reference checks passed in the
complete local Windows checkout. No unrelated protocol or existing confirmation
code is changed.

## BGP candidate route-state consumer — additive source candidate

The separate `deep::bgp_state` API is specified in [BGP_STATE.md](BGP_STATE.md). It consumes
normalized captured/imported observations with exact inherited provenance,
source/session/generation/direction isolation, explicit replay and withdrawal
outcomes, conflict alternatives and fail-closed identity quarantine. Candidate
state is not an endpoint RIB, best path, causal proof or authoritative source.
There is no automatic change to existing decoder/event/CLI output, no cross-source
join and no new dependency.

The worker authored 31 native tests; the candidate was then reviewed and passed
the local Windows native product/workspace gates. The accepted review repaired
payload digest computation, missing-direction state mutation and attribute-local
MP bounds. Direct producer budget parity, broader capability/session semantics,
Linux/runtime, live, scale, fuzz and normative qualification remain open.

## DNP3 workflow candidate — native gates run locally

The additive worker slice based on
`fcbfddbf5565b25e46d9849aef39698c47713bbc` is specified in
[../DNP3_WORKFLOWS.md](../DNP3_WORKFLOWS.md). It preserves the reviewed root layouts
and adds bounded link admissibility, source-bound confirm/unsolicited/class/event/
time observations, stricter witness-verified candidate pairing, duplicate/conflict
boundaries, rejected-link ranges, and incomplete-safe root/streaming/deep projections.
Root complete-message object completion is retained; bounded Group 0 attribute
envelopes and root Group 70 free-format file-object variations 3--8 are now
supported as exact, hash-safe evidence; bounded opt-in multi-APDU candidate
reconciliation is now available, while endpoint-authoritative completion, Group 70
authentication variation 2 and secure semantics remain open. A separate
TCP-only streaming confirmation projection is now integrated on top of verified
fragment witnesses; generic transaction events and UDP datagram boundaries are
unchanged.

The worker environment lacked Rust and returned only reference-vector/package
receipts; those receipts are not native proof. This isolated Windows integration
has now passed fresh root format/build/test/clippy, product debug/release and
feature-matrix gates, streaming debug/release and clippy gates, and the focused
DNP3 workflow suites. Those results validate this candidate slice, not complete
protocol or release qualification. Full platform/live, scale, fuzz, external
corpus, secure and normative gates remain open. The next smallest semantic slice
is an independent DNP3 endpoint-authoritative file-transfer/reconciliation or secure-semantics
package with explicit review of this recent Group 70 integration, the streaming
integration, and any other relevant implemented pieces.

Baseline: `5225e9aa794b91d5d0fdf6d8d313a957d6a337f1`.
Current Tier-A integration base: `e2a411ced571390ffe414cfbdf4a94fca3814aad`.
Controlling request: `IMPLEMENTATION_HANDOFF.md`; original snapshot/streaming
contracts remain in force. This is a source candidate, not release promotion.

The remaining implementation order and acceptance criteria are maintained in
the controlling product and current-state documents. This status file records
historical integration evidence only; verify current source and validation
receipts before relying on any older result.

| Feedback area | Delivered change | Exact remaining boundary |
|---|---|---|
| Rust-owned TCP history | New `history/` workspace: source-bound journal, automatic scoped generation/epoch hypotheses, bounded tuple eviction/reload, source spans, external interval sort, late conflicts, quotas, cancellation, replay verification and prefix recovery | Integrated Windows format, debug/release test, example-build and Clippy gates pass; unlimited IP/application history, arbitrary endpoint truth and O(1) resume are not implemented |
| Deeper protocol semantics | BACnet services and CIP path/status fields wired into `Protocol::decode`; Tier-A adds source-bound DNP3 per-fragment object reports and Modbus bit/register semantics through root and streaming consumers | Partial subsets only; no normative edition approval, deep multi-APDU DNP3 object completion or complete MMS stack; root complete-message decoding is already available |
| Opt-in depth/history addendum | Bounded deep reports across industrial, fieldbus, ISO/MMS/S7, OPC UA and IEEE 802.15.4/Zigbee families; verified packet-map sink; bounded Group 70 file-transfer candidate reconciliation; typed history ranges; stateful history-app consumer; explicit optional OPC UA transform boundary | Ten direct depth tests plus reconciler unit cases, product/history compiles and real PCAP/history smoke runs pass; no complete TCP replay, timing replay, secure decryption, endpoint-authoritative transfer state or normative qualification |
| Semantic evidence depth | 18 native semantic cases, malformed/ambiguous/conflict fixtures, five semantic PCAPs, and complete NDJSON/TLV projection parity | No normative protocol qualification; the five captures are targeted regression evidence, not representative coverage |
| First divergence | Comparison v2 considers earlier uncovered fields in the same layer and partial current-layer coverage | Not complete adapters for every protocol; no consensus or correctness winner |
| Old research artifacts | Exact v1 comparison algorithm retained; bundle verification dispatches by recorded report schema | Producer authentication remains outside a hash-only bundle |
| Investigation GUI | New coverage distinctions visible in Research; existing interface uses hardened real backend | Native-browser qualification harness included; no new packaged desktop installer or history view |
| Worker lifecycle | Persistent cancellation, direct-child termination, operation timeout, sampled logical disk budget, durable atomic state retries, bounded diagnostic read, closed SQLite/pipe resources, correct committed-prefix accounting | No claim of a kernel quota, adversarial local-owner sandbox or complete Windows descendant-job containment |
| C ABI | Real linked consumer harness: null/limits, one-shot state, no-clobber small buffers, exact output, 100 sequential/concurrent lifecycle cycles | Rust FFI format/test/release/Clippy, library-build and real linked C execution gates pass under the prepared Windows MSVC environment; other ABI/OS combinations remain open |
| Qualification | Independent history-format verifier; Rust tests/fuzz target; portable regressions; real native-browser and linked-ABI gate scripts; guarded ZIP installer | Fresh integrated follow-up receipt: 26 required gates PASS, including linked ABI, and six independent classes NOT_RUN; the separate real browser smoke gate passes. Sustained fuzz, operational corpus, 50-500 GiB measurement, actual NIC capture and Windows/Linux installers remain unqualified |

Fresh integrated Windows evidence now covers the new Rust modules: the follow-up
driver records 26 required PASS gates across Python, GUI models, catalog maintenance,
root, streaming, product, FFI and history workspaces, including linked C-ABI
execution. The separate product qualification
run passes its 191-test Python suite, native feature matrix and baseline regression
gate. The independent browser check passes with real requests and native-worker
source binding; the follow-up driver intentionally records that class as NOT_RUN
because it is an independent gate. These are local engineering receipts, not
release promotion or proof of normative protocol correctness.

## Preserved architecture

No dependency from the core parser to external analyzers, SQLite, GUI frameworks,
network services or third-party protocol libraries is added. Existing Python SQLite
and browser tooling stay above the Rust evidence boundary. Fuzz dependencies stay
in an explicitly separate development workspace. No private reference document,
internal product name or private corpus is incorporated into this public code.

The older reference designs' useful objectives (offline safe Rust, layered parsing,
feature profiles, machine-readable output, FFI/live adapters and conformance work)
remain design inputs. Their former GUI, storage and breadth exclusions do not limit
this product. Their broad performance and completeness claims are not inherited.

## Required next native action

The integrated checkout has completed the new native matrices and repaired the
validator/fixture portability defects found during that run. The Windows linked
C-ABI gate now has a real PASS receipt; the next required engineering action is
sustained-fuzz, large-capture, normative-protocol and installation qualification.
The browser smoke gate has a direct PASS receipt, but its full accessibility,
packaging and upgrade coverage remains open. Fix compiler, borrow, lint or
semantic failures without relaxing assertions; preserve fresh receipts during
each gate.

Commands and promotion conditions: `FOLLOWUP_QUALIFICATION.md`.
Depth contract and current evidence: docs/product/DEPTH_CONTRACT.md.
History contract: `../history/CONTRACT.md`. Protocol depth: `SERVICE_FIELDS.md`.
