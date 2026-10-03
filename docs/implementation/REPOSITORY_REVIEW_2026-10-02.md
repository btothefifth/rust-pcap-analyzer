# Repository review and continuation plan — 2026-10-02

## Decision and scope

The repository is a substantial offline evidence-analysis implementation with
working core/streaming contracts and newer product, BGP, history, research,
desktop, C-ABI, and optional acquisition layers. Continue from this architecture.
The next semantic package is imported BGP4MP session/RIB completion; first close
the storage, validation, packaging, and current-state gaps below. This is an
engineering source candidate, with qualification dimensions still open.

Reviewed baseline: **`ce0fe7fe77e3a99715567dd89a6fae680d944d27`**, published
`main`, whose commit message is “Complete cross-platform validation notes”.
The other pre-existing remote branch, `improve/product-quality-audit`, points
to that same commit. At review inventory time GitHub lists no pull requests,
issues, or tags for this repository. This review uses a new branch and does
not promote or alter `main`.

The reachable Git history is **one parentless snapshot commit**, confirmed
locally and through GitHub's commit API. The clone is not shallow. Earlier
development is described in the changelog, dated slice contracts, validation
notes, and older Actions runs, but those descriptions are not a reconstructable
sequence of ancestor diffs. Claims about earlier work below are reconciled
against the current snapshot. This audit cannot certify every historical diff
or recover omitted historical review discussions.

The audit includes a complete tracked-file inventory, all Python/JSON/TOML
syntax inventories, documentation navigation checks, current-state and contract
reconciliation, targeted inspection of important producer/consumer and storage
boundaries, existing portable tests, independent small defect probes, and
exact-commit hosted CI inspection. It is not an exhaustive line-by-line review
of all Rust functions, a normative protocol audit, or a security certification.
One reviewer owns this report; independent evidence comes from fixture oracles,
observed APIs/filesystem results, source manifests, and hosted execution.

No parser or application behavior is changed by the review branch. Its durable
changes are this report, the current-pointer link, and repository agent guidance
preserving the owner's disk constraint. Defect repairs are future implementation
packages with their own tests and receipts.

### Operating contract

- Keep total project storage **below 50,000,000,000 bytes**, including `.git`,
  build trees, project-specific caches, captures, workspaces, copies, and scratch
  outside the checkout. Keep everyday usage far below that ceiling.
- Use one filtered checkout, tiny synthetic fixtures, and bounded disposable
  scratch. No large capture downloads, full release copies, or local toolchain
  installation are necessary for this audit.
- Treat code, local execution, hosted execution, profile coverage, browser/native
  joins, source authenticity, normative correctness, scale, and release promotion
  as distinct evidence states.
- Preserve the core's offline/dependency-free, bounded, no-overwrite, source-bound
  behavior. No real NIC capture, traffic injection, production deployment,
  encrypted-capture processing, or automatic authority enablement is part of
  this task.
- The mutation owner is the review branch author. The publication boundary is
  a documentation/guidance commit and draft PR. Rollback is to close the draft
  or revert those files; no running application is affected.

## Inventory and work already delivered

Baseline inventory: **675 tracked files**, including 160 Rust files, 80 Python
files, 64 Markdown documents, 21 JSON files, 12 TOML files, 9 lockfiles, 4 workflow
files, and 3 C files plus the ABI header. The 126 PCAP and 4 PCAPNG fixtures total
**39,529 bytes**. The largest tracked file is the approximately 214 KB research
catalog. The checkout's measured allocated footprint before documentation changes
was **8,077,312 bytes**. The upstream GitHub size field is 888 KiB; that compressed
repository metadata is not the local checkout's allocated size.

| Surface and owners | Delivered behavior corroborated by current source/contracts | Remaining boundary |
| --- | --- | --- |
| Core `src/`, `tests/` | Classic PCAP endian/precision variants, PCAPNG sections/interfaces/metadata, borrowed and streaming containers, writers, exact clocks, source hashes, packet offsets, sidecar verification, deterministic JSON and CLI | Snapshot analysis is in memory; default input cap is 256 MiB. Opaque metadata retention is broader than decoded semantics. Index verification reparses source. No out-of-core or arbitrary allocator/RSS guarantee. |
| Packet/transport `wire`, `fragment`, `tcp`, `engine`, `provenance` | Link/network parsing, checksums, bounded IP reconstruction, TCP generations/wrap/reordering/duplicates/gaps/conflicts, packet-to-stream spans and explicit policies | Offline hypotheses do not reproduce every endpoint's TCP behavior. Ambiguity and discarded history cannot be silently repaired. |
| DNP3 and Modbus root/streaming/deep paths | DNP3 CRC/link/transport/application framing, object/qualifier subsets, complete-message projection, Group 0 attributes, Group 70 variations 3–8, confirmation/workflow candidates; Modbus MBAP, common function shapes, bit/register and configured-map evidence | Non-secure partial profiles; no device truth, authenticated file transfer, complete object database, secure authentication, or full normative conformance. UDP remains datagram-local. |
| `streaming/` | Incremental producer, bounded active state/windows, detector/plugin ownership, typed evidence and hash-chained NDJSON, explicit cuts and terminal source binding | A window discards history; `complete_protocol_history=false`. Plugins are trusted in-process code. Streaming completion is not complete application history. |
| `product/` framing/layer/deep/output/TLV | Opt-in `pcap-product` and `pcap-depth`, feature/profile registration, supplemental link observations, partial industrial/IT fields, provenance composition, packet map, deep reports and typed binary output | Registration is not decoding qualification. Profiles are not a security allowlist. Secure services, device/object models and broad conformance remain partial or unsupported. JSON/TLV schemas remain candidates. |
| Captured BGP producer/session/RIB/manager/pipeline/store | Source-bound OPEN/UPDATE/control occurrences, bilateral grammar context, scoped candidate state, atomic multi-route actions, gaps/resets/EOR, captured direction/event order, sealed source-message journal and fresh replay/state/query/export | Candidate session/RIB observations are not actual negotiation, installation or reachability. Graceful/LLGR timer semantics and full declared-profile qualification remain open. |
| Imported BGP/MRT/import/replay/state | Bounded TABLE_DUMP_V2 and BGP4MP/ET container parsing; exact source ranges; source-ordered capability-gated BGP4MP events/candidates; sealed `bgp.mrt`; compact references, batch admission, logarithmic peer lookup, fresh query/export; explicit collector directionlessness | Existing generic candidate reduction and generation boundaries are real. Complete imported session Adj-RIB-In/reset/teardown semantics, malformed BGP4MP preservation, BMP, and broad capture/BGP4MP semantic parity remain open. |
| BGP semantic identity/policy/association | Versioned source-neutral identities for a supported capture/TABLE_DUMP_V2 subset; consistency checks and opaque-only unsupported evidence; configurable library policy traces; generic evidence association with explicit clocks/dimensions | AS4 identity and complete supported-row reconciliation, persisted policy exposure, richer queries and multi-source persisted association remain unfinished. Matching meaning must not merge source partitions or create authority. |
| `history/` | Automatic TCP observation/generation/epoch hypotheses, disk journal, tuple spill/reload, bounded external sort, exact source witnesses, sealed indexes, late-conflict queries, restart-by-replay and torn-tail controls | This implementation exists. It is not complete endpoint/application history, checkpoint-position resume, unlimited fragment spooling, or measured 50–500 GB capability. |
| `history-app/`, `deep::continuation` | Finalized history ranges feed bounded stateful application framing across pages; real gaps/conflicts cut state; explicit incomplete and aborted results | Separate workspace, limited protocol hypotheses, no full endpoint/time replay. Hosted validation currently does not select this workspace. CLI has a malformed-identifier bug below and a fixed 8 GiB output cap. |
| Research/evidence Python tooling and catalog | Source-bound indexing, qualification labels, attributed adapters, ordered comparison v1/v2, coverage-aware divergence, bounded minimization, raw-witness bundles and verification | 136 catalog cases across 68 families have maintenance PASS but every family's qualification is BLOCKED. Protocol-specific adapters, reviewed clauses, executed corpora and adjudication are incomplete. Agreement never establishes truth. |
| Desktop/web/worker/store | Loopback Host/Origin/token checks, explicit roots, isolated worker, incremental SQLite views, raw packet checks, virtualized/paged UI, research views and export, cancellation and bounded state-file retries | Trusted local-user application; aggregate retained storage and research listing are not bounded as claimed. Full browser/native/accessibility/install/upgrade evidence is incomplete. A model test or container-mode HTTP test is not a Rust/browser join. |
| `product/ffi/` | Isolated unsafe ABI boundary, opaque monotonic handles, bounded input/output, one-shot analysis, null/limit/error statuses, serialized calls, caller-owned output, panic catch and real C harnesses | Full linked harness selection differs by platform. Allocator abort and invalid native pointers are outside panic containment. Injected panic coverage and supported-ABI qualification remain open. |
| `product/live/` | Separate explicit Linux AF_PACKET acquisition adapter, no-clobber file publication, bounded packet/byte settings, kernel timestamp/drop observations, deterministic socket-denial compile mode | Actual authorized capture and end-to-end Rust/live integration are unqualified. Compile and injected denial do not establish NIC behavior or lossless acquisition. |
| Fuzz/benchmark/package/CI | Separate development-only fuzz graphs, state/format targets, independent mutation/CLI oracles, benchmark drivers, pinned Actions, native/streaming matrices and product workflow | Sustained campaigns, performance/RSS, representative corpora, security/normative review and release packaging remain unfinished. Package inventory is currently broken for the expanded tree. |

The early core and hardening work is described in `CHANGELOG.md`,
`docs/ENGINEERING.md`, `docs/VALIDATION.md`, and `docs/streaming/CONTRACT.md`.
The additive product reconciliation is in `IMPLEMENTATION_HANDOFF.md` and
`FOLLOWUP_STATUS.md`; the newer active BGP plan is `BGP_COMPLETION.md` and
`BGP_COMPLETION_HANDOFF.md`. Retain those distinct scopes instead of treating an
old limitation list as absence of code that has since been added.

## Findings, ordered by consequence

Priority meanings: P1 is a required correction before the affected surface is
relied on or promoted; P2 is a bounded correctness, coverage, or maintenance
defect. These priorities do not imply that the unmodified offline core is unusable.

### R1 — P1: per-worker budgets do not bound retained project storage

Owners: `tools/desktop/server.py:156`, `:184`, and
`tools/desktop/resources.py:100`.

`Manager.save_research` accepts each artifact up to 8 MiB but does not reserve or
charge it against `Manager.disk_budget`. Every call creates another research
directory. `export_bundle` similarly creates a new ZIP each time. Completed jobs
and completed research/export directories have no aggregate retention admission.
The worker guard scans only direct files in one job directory and exists only
during worker execution; nested research/export data and old jobs are outside it.
One active analysis job therefore does not bound cumulative storage.

Small observed falsifiers, both cleaned up:

- A guard with a 65,536-byte budget saw a nested 70,000-byte research file as
  peak **0**, with no stop.
- A manager configured for 65,536 bytes accepted ten 8,192-byte research
  artifacts, retaining **82,505 bytes** including receipts/ownership metadata.

Correction: one workspace/project admission owner must count existing retained
data and reserve expected temporary/output peak before writes. Apply it to jobs,
research imports/runs, exports, caches and partial results; release reservations
on failed publication. Bound cardinality and expose retention/cleanup without
silently deleting evidence. Exercise exact-limit/one-over, concurrent writers,
failed writes, nested files, old jobs, and restart. A filesystem quota may be a
separate backstop, but sampled logical byte counts cannot claim to be that quota.

Existing history defaults are 1 TiB for source and disk; Python source archive
also defaults to 1 TiB; the desktop defaults to 10 GiB per job. These are library
limits, not permission to use that capacity here. The owner's aggregate ceiling
is below 50 GB. This review executes none of those default workloads.

### R2 — P1: CI does not cover the complete dependency and workspace frontier

Owner: `.github/workflows/product-qualification.yml:4–17`, `:40–72`; root and
streaming workflows; `scripts/validate_followup.py`.

Product CI is path-filtered to product/tools/desktop, `scripts/*product*`, and
its own workflow. Changes to `src/` or `streaming/` can alter product path
dependencies without selecting product tests. `history/` and `history-app/`
are absent from automatic workflow commands and trigger paths. The follow-up
driver includes history but still omits history-app. Python discovery under
`tools/tests` omits the 61 BGP vector tests in `product/tests/*vectors.py`, the
15 semantic-tool tests, and the three OPC UA transform tests. Product CI selects
default and no-default features, rather than all six separately documented profiles.

The Linux workflow links the small 100-cycle `ffi/harness.c`, while the richer
null/error/concurrency consumer is `ffi/tests/linked_contract.c` and the helper
`scripts/check_linked_abi.py`. Windows product CI builds FFI but does not link/run
that consumer. Live acquisition is only compiled by product CI; its injected
denial is not selected there. macOS product qualification is not configured.

Correction: map every workspace and semantic proof entrypoint to its triggering
dependencies. Add bounded history/history-app gates, independent vectors, semantic
projection parity and the appropriate linked ABI/denial gates. Preserve exact
selectors and truthful platform exclusions. Use hosted builds on this machine's
current low-footprint review path. A broader CI run must still be reported only
for its actual selected surfaces.

### R3 — P1: packaging omits expanded runtime/test trees and ships stale evidence

Owners: `scripts/package.py:13–31`, `evidence/source-manifest.json`, and
`evidence/delivery-check.json`.

The package allowlist omits **all** of `product/` (353 tracked files), `tools/`
(48), `history/` (25), `history-app/` (4), and `desktop/` (6). Nevertheless it
includes expanded docs and scripts such as `validate_product.py` and
`validate_followup.py`, which require those omitted trees. Even a deliberately
core-only archive includes a streaming workflow importing absent `tools/tests`.
The capture suffix filter also excludes synthetic fixture roots outside
`tests/fixtures`, so expanding only the directory allowlist is insufficient.

Read-only comparison found **136** retained manifest entries, **34** current
file hash mismatches, and **76** additional files selected by the current package
enumerator but absent from the manifest. No manifest path is missing. The old
delivery receipt describes a 139-member extraction with a different source
identity; it does not attest to this tree. The old local root receipt's source
identity is `5da1ea5ab194a852d4d51038b27a22f9c87400ea07aac5f1e293540797e14171`;
the same validator's identity function on the reviewed baseline yields
`f9fb4c35a29aa8f7cdc4885a7657f17fe44f65c4f18a32751917fe9066b89043`.
That mismatch invalidates reuse as an exact-tree receipt; it does not prove a
particular native implementation failed.

Correction: choose explicit core and expanded-product package profiles with
dependency/fixture closure. Derive membership from a reviewed source inventory,
exclude generated evidence/private captures, refresh manifests, and test the
promised entrypoints in a small fresh extraction. Use bounded temporary storage
only for this future packaging gate. Do not copy stale PASS receipts into a new
package as current evidence. No archive was generated during this review.

### R4 — P2: research listing performs unbounded work before its 100-row cap

Owner: `tools/desktop/server.py:178–181`.

The list comprehension sorts and opens **every** retained research receipt,
then slices to 100. The response cap does not cap parsing, memory, I/O or work.
The lack of retention admission in R1 makes this reachable by normal repeated
research operations. A small probe with 100 valid receipts followed by a malformed
101st receipt raised `InvalidResearch` instead of returning the first 100. The
101st receipt should not be read for a page capped at 100.

Correction: a bounded, deterministic paginated index/cursor and an examined-entry
budget, with explicit incomplete/error behavior. Test a bad receipt beyond the
selected page, large directory cardinality using tiny files, and page boundaries.
Do not merely move the slice if sorting still enumerates every retained directory.

### R5 — P2: history-app accepts a UTF-8 byte count before unsafe string slicing

Owner: `history-app/src/main.rs:11–16`.

The generation argument checks `len() == 64`, then slices the Rust string at
every two-byte boundary. Unlike `history/src/main.rs::generation`, it does not
first require ASCII. For example, one ASCII `a`, then `é`, then 61 ASCII `a`
characters is exactly 64 UTF-8 bytes; the first `0..2` slice ends inside `é`
and panics. That bypasses the CLI's ordinary reported-error path before opening
the source. This is code-derived and has not been executed natively on the review
host, whose Rust compiler is absent.

Correction: reuse a shared ASCII/hex parser or validate bytes without UTF-8
slicing. Native CLI cases must cover this 64-byte input, ordinary invalid hex,
wrong length, and a valid identifier; all invalid inputs must produce a typed
usage/error result without unwinding. Keep that gate in history-app CI.

### R6 — P2: active inventory and chronological docs disagree with current code

Owners: `docs/product/bgp-support-matrix.json`, its four structure-only tests,
README/current pointers, product status/roadmaps, and retained evidence files.

- BGP-S008/S011 still list restartable replay/query/export as outstanding,
  although captured persistence and the shared CLI exist. S010 lists source-byte
  verification at import and MRT message normalization as absent, despite the
  sealed store and partial BGP4MP replay. These rows need narrower residuals and
  links to their current store/replay tests.
- S012 says Linux CI remains open without separating existing root/streaming
  observations from product/history and normative coverage. The matrix tests
  establish row/path existence, not truth of the remaining-work prose or execution.
- `PLATFORM_ROADMAP.md` still says DNP3 first/highest priority; the current
  implementation pointer and BGP completion handoff prioritize BGP4MP completion.
  README describes `docs/CURRENT.md` as current, although that page explicitly
  declares itself a September 20 baseline snapshot.
- Historical counts such as 135 root selectors do not describe the current
  275-selector manifest. Older FFI/browser/worker BLOCKED receipts coexist with
  later platform-specific acceptance notes. Preserve them as historical evidence
  instead of flattening them to one PASS or one permanent BLOCKED state.
- An optional authorized OPC UA transform exists outside the Rust parser, with
  only Sign-mode tests in its own module. Broad “no decryption” prose needs that
  explicit isolated exception, without claiming qualified AES/secure-channel
  behavior or allowing it to become an implicit parser dependency.

Correction: keep one thin current pointer and dated, scoped historical receipts;
reconcile the matrix from current code and owning consumer tests. Do not overwrite
the controlling normative boundaries or mark a profile qualified to make prose
agree. Renew execution evidence separately from editing documentation.

## Test and CI evidence ledger

All local checks used the baseline source before review edits, Python 3.14 on
Linux, bytecode disabled, and disposable scratch with a 64 MiB logical stop
budget. The already-bundled Node executable supplied the JavaScript check without
installation. No Cargo, rustc, or rustup was present; no Rust build was attempted
or presented as locally executed. No source captures were changed.

| Selector / observation | Actual result | What it establishes |
| --- | --- | --- |
| `python3 scripts/static_check.py` | PASS; 43 Rust files inspected structurally, 24 module paths, 275 selectors; Pygments delimiter check | Structure/manifest checks, not Rust syntax, types or execution |
| `python3 scripts/make_fixtures.py --check` | PASS; 23 fixtures | Existing deterministic fixtures match builder; no regeneration |
| `python3 scripts/reference_verify.py` | PASS; 23 hashes, 11 container cases, 2 rejection cases | Independent fixture/container/protocol checks, not native execution |
| `python3 scripts/test_oracle.py` | PASS; 10 tests | Fixture/oracle invariants |
| `python3 -m unittest discover -s tools/tests -v` | PASS; 202 tests, no skips on this host | Python/HTTP/worker/SQLite/research contracts, including real container-mode subprocesses |
| `python3 -m unittest discover -s product/tests -p '*vectors.py'` | PASS; 61 tests | Independent BGP vector/arithmetic evidence; no Rust comparison implied |
| `python3 scripts/test_semantic_tools.py` | PASS; 15 tests | Semantic tooling properties |
| `python3 -m unittest tools.depth.test_opcua_crypto -v` | PASS; 3 tests | Explicit authorization, Sign-mode MAC and tamper behavior; encrypted AES path untested |
| Bundled `node --test desktop/web/model.test.mjs` | PASS; 11 tests | Integer/time/virtualization model semantics; not a real browser/native join |
| `python3 -m tools.research audit` | Maintenance PASS; qualification BLOCKED; 136 cases/68 families | Catalog maintenance only; all 68 families retain qualification gaps |
| Parse all tracked Python/JSON/TOML; resolve Markdown file links | PASS; 80/21/12 files; no broken file targets | Syntax/document navigation, not schema conformance or normative claims |
| Enumerate package membership and compare retained manifest hashes | R3 reproduced | Artifact closure/receipt drift; no ZIP created |
| Tiny nested-budget, repeated-research and 101st-receipt probes | R1/R4 reproduced | Real owning API/accounting failures; all probe directories removed |
| `cc -std=c11 -Wall -Wextra -Werror -fsyntax-only` for three C files | PASS | C syntax/warnings only; no Rust linking |
| Build Linux adapter with `-DPCAP_TEST_DENY_SOCKET`, then run `test0` denial | Expected exit 3, EPERM; no output/partial | Fail-closed injected acquisition refusal; no socket acquisition or real traffic |
| Rust/native linked ABI/history/application tests on this host | BLOCKED: toolchain/library absent | No local native proof claimed |
| Sustained fuzz, representative real corpus, RSS/throughput, security/normative review, installers, actual NIC capture | NOT RUN / NOT ESTABLISHED | These remain independent qualification gates |

The main portable batch's sampled scratch high-water mark was **1,240,295
bytes**. The separate denial executable was **21,456 bytes**; defect probes used
kilobyte-scale data. All scratch roots were removed. Sampling is not an exact
physical filesystem or process-memory peak. Retained project additions are small
text files; there are no build trees, downloaded captures or archive copies.

### Hosted baseline evidence

The following observed successful runs bind to the exact baseline commit above:

- [native-validation #36873154900](https://github.com/btothefifth/rust-pcap-analyzer/actions/runs/36873154900):
  Linux, Windows and macOS root/native jobs succeeded, including ordered validation
  and API docs.
- [streaming-evidence-contracts #36873155015](https://github.com/btothefifth/rust-pcap-analyzer/actions/runs/36873155015):
  Linux, Windows and macOS jobs succeeded for their selected Python/root/streaming
  checks.

The latest previously recorded additive-product run is successful on the older
`b3497cab10393d286f58d14016b7121dcd5c3324`, not on this baseline. A new
[manual additive-product run #37089585782](https://github.com/btothefifth/rust-pcap-analyzer/actions/runs/37089585782)
was dispatched on **`ce0fe7fe77e3a99715567dd89a6fae680d944d27`** during the
audit. Its terminal result was inspected: **SUCCESS on Ubuntu 22.04 and Windows**,
including product format/debug/release, the isolated FFI build, selected Python/JS
models and baseline regressions. Linux also linked and ran the small C ABI client;
that step was explicitly skipped on Windows. No Actions artifacts or log ZIPs
were downloaded locally.

Hosted results remain limited to the commands in those workflows. They do not
qualify history/history-app, complete six-profile coverage, full rich linked ABI,
normative correctness, real corpus, scale, security or release readiness.

## Ordered execution plan and acceptance

### Package A — baseline controls and evidence closure

Close R1–R6 in small reviewable changes. Storage admission is the first local
operational seam; validation/dependency coverage is the first publication seam.
Bind matrix rows to current direct consumers, correct packaging closure, and add
the tiny listing/identifier regressions. Do not mix broad protocol expansion into
these repairs. Freeze exact candidate identities for each native/hosted receipt.

Acceptance: exact storage-boundary rejection without losing source/evidence;
bounded research pages; malformed CLI input returns a normal error; all workspaces
and required independent selectors execute on declared platforms; package
membership/entrypoints match its declared profile; docs distinguish current,
historical and still-unqualified evidence. Reuse unaffected evidence only when
its dependencies and identity remain valid.

### Package B — complete imported BGP4MP session candidate state

Owning seams: `bgp::mrt` source-order records -> checked imported observation /
generation carriers -> session observer and imported Adj-RIB-In -> sealed fresh
replay/state/query/export. Reuse the existing decoder/state owners; do not invent
captured `PacketId` or direction evidence for collector snapshots.

1. Specify and implement imported announcements/withdrawals and reset/teardown
   disposition beyond the existing candidate/event reduction. Preserve source,
   checkpoint, session, generation, peer, path ID, clock and trust partitions.
2. Retain malformed BGP4MP source records with exact ranges through archive/replay
   without treating them as successful normalized routes. Missing or contradictory
   OPEN/FSM/relationship context must remain unresolved/quarantined.
3. Define and test AS4_PATH/AS4_AGGREGATOR semantic identity and every supported
   attribute/NLRI row. No fingerprint for incomplete/opaque route meaning.
4. Join independently constructed equivalent captured and BGP4MP UPDATEs through
   real producer/store consumers. Require equal supported meaning and distinct
   source/provenance/authority/state partitions.

Acceptance: announce -> replace -> withdraw; reset without fabricated per-prefix
effects; unaffected sibling peer; retry/tuple reuse; exact replay and altered-record
quarantine; malformed/truncated records retained; exact/one-over budgets; atomic
failure; fresh-process parity; timestamps never reorder records. Keep source
authenticity, installed routes and reachability false. Follow the owning BGP
completion handoff's explicit reset contract rather than deriving endpoint truth.

### Package C — persisted policy, richer queries, common evidence association

Add a strict bounded versioned policy profile and `bgp policy` consumer, with
explicit router-local inputs and unresolved outputs for missing reached inputs.
Expose prefix/family/peer/source/checkpoint/status filters. Reference sealed
captured/MRT stores by digest, preserve their namespaces and clocks, and join the
existing association engine without copying source files or merging equal
fingerprints into one source occurrence.

Acceptance: deterministic traces/permutation behavior, missing-config rejection,
MED-scope and tie cases, complete alternatives, mixed trust/coverage, fresh replay,
explicit clock policy, no-overwrite and exact canonical output limits.

### Package D — bounded BMP and declared BGP profile closure

Only after BGP4MP and persisted multi-source contracts stabilize, add BMP common
and per-peer containers with original bytes/identity, explicit supported records,
opaque unknowns, and shared embedded BGP decoding. Reconcile every support-matrix
row against actual consumer execution. Sustain wire/state/store/policy fuzzing and
lawful collector/capture disagreement analysis with minimized witnesses.

Acceptance: independent primary-spec vectors, malformed/unknown neighbors,
source-partition non-collapse, corruption/restart, and exact-commit platform
receipts. Corpus licensing, normative adjudication and source authenticity stay
separate from parsing and hash identity.

### Package E — broader platform depth and release qualification

Then continue the current completion contract's order: transport/application
history and remaining DNP3 semantics; Modbus TCP/RTU; BACnet; CIP; IEC/ISO/MMS/S7;
OPC UA; remaining industrial and IT families; browser/accessibility/packaging.
Use one source-bound end-to-end vertical slice at a time, with explicit unsupported
neighbors rather than changing catalog labels before consumers are proved.

Large-capture and sustained-fuzz qualification must use measured hardware,
input/config/compiler identities, process-tree RSS, allocated disk peak, output
amplification, duration, coverage/crash receipts and recovery bounds. The older
50–500 GB qualification aspiration **does not authorize a 50–500 GB local dataset**
on this host. Keep fixtures/minimized replays small, avoid raw duplication, and
place any independently authorized larger campaign on a suitable other host.

## Stop, reopen, and completion boundary

This review task is complete when its small coherent files are committed on the
new branch, published as a draft PR to `main`, and remote base/head/file identities
are checked. Report the new PR's CI separately from baseline runtime evidence.
Do not merge, release, deploy, or claim the discovered defects repaired.

Reopen affected findings when code, contracts, selected tests, workflow triggers,
storage behavior, or source identity changes. Close a defect only after its owning
consumer passes a representative positive case and the specific harmful/boundary
case; a changed status sentence or a green unrelated suite is insufficient.
