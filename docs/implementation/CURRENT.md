# Current implementation pointer

## Active objective work

The additive incremental MRT, checkpoint chronology, evidence-manifest and
external BGP comparison increment is governed by
[the stream evidence contract](../product/BGP_STREAM_EVIDENCE.md). The
[stream validation receipt](../../evidence/bgp-stream-validation.json) records
its actual source generation, review and finite validation outcomes; a pending
or absent receipt establishes no passing gate. Existing receipts remain bound
to their own source generation.

The repository-owner-authorized objectives 1–4 implementation and exact
evidence record are tracked in the [objective ledger](OBJECTIVES_1_4.md). The
ledger records source ownership, implementation progress, receipts, and
remaining qualification gaps; it does not change the acceptance conditions in
the [BGP completion contract](../product/BGP_COMPLETION.md). Until accepted
receipts are recorded there, in-progress work does not close a gate.

## Repository review

The [2026-10-02 repository review](REPOSITORY_REVIEW_2026-10-02.md) inventories
the published baseline, records independently checked findings and validation
limits, and orders the next work. It also records the local project storage
ceiling of 50 GB. This review adds no parser implementation or qualification
claim; the controlling BGP contract and the priorities below remain in force.

## Objective and authority

Continue the declared offline BGP evidence profile in
[BGP completion](../product/BGP_COMPLETION.md), with RFCs and IANA registries as
normative authority and other analyzers as disagreement probes only. The design
docs remain authoritative for product intent. This pointer is the concise
current-state view; older slice receipts are historical unless cited below.

## Current implementation candidate

The current O14-1 candidate extends imported BGP4MP replay into the canonical
source-scoped Adj-RIB-In reducer, preserves malformed complete embedded records
as rejected evidence, and advances only the matching peer partition at reset
boundaries. A generation boundary retains history and does not invent
per-prefix withdrawal evidence. Captured, MRT, and BMP route producers now use
the versioned source-neutral semantic identity for its supported profile;
persisted consumers provide bounded replay, state, query, policy, export, and
cross-source association paths for captured, MRT, and BMP stores. These remain
offline candidate-evidence paths: equal identities do not merge partitions or
establish endpoint negotiation, source authenticity, installation, or
reachability. The owning contracts are [MRT ingestion](../product/BGP_MRT.md),
[MRT source storage](../product/BGP_MRT_STORE.md), [BMP ingestion](../product/BGP_BMP.md),
[persisted consumers](../product/BGP_PERSISTED.md), and
[semantic identity](../product/BGP_SEMANTIC_IDENTITY.md).

The same candidate includes work across the repository-owner-selected storage,
bounded-listing, validation/package, CLI parsing, and operator-truth objectives.
The [objectives 1–4 ledger](OBJECTIVES_1_4.md) records those source seams,
component receipts, and remaining gates. Implementation scope and validation
outcome are separate; use the receipt below for the exact assembled generation.

## Current validation status

PR review repairs are governed by the
[O14-F2 feedback receipt](../../evidence/pr-feedback-round2-validation.json) and the
repair contracts in the [objective ledger](OBJECTIVES_1_4.md). The
[O14-F1 receipt](../../evidence/pr-feedback-validation.json) describes the preceding
`225b730` source generation. A pending receipt
does not establish a passing result. The earlier
[O14-1 validation receipt](../../evidence/objectives-1-4-validation.json)
remains bound to its recorded source generation preceding those repairs.
Component observations and finite synthetic evidence are not a substitute for
same-generation proof. Open normative, real-corpus, sustained-fuzz, scale/RSS, security, and
exact-head platform gates remain unqualified unless their own receipts say
otherwise. The historical results below apply only to their stated revisions.

## Historical validation receipts (not current candidate validation)

Windows-only evidence, collected 2026-09-25 with Rust 1.85.1:

- Product all-target debug tests: 447 passed; release tests: 447 passed.
- Product warnings-denied Clippy and root, streaming, product, and FFI rustfmt
  checks: passed. Root, streaming, product, and FFI locked debug/release tests,
  Clippy, and release builds passed.
- All six product feature profiles passed: no-default, standard, extensions,
  industrial, industrial-full, and binary.
- Ordered root validator: all 13 steps passed, including root debug/release,
  locked offline check/build/Clippy, fixture/oracle checks, CLI hardening, and
  mutation checks. Its source-unchanged receipt passed.
- Full product qualification ran 202 Python tests (3 skipped), catalog audit,
  and JavaScript model tests successfully. Its overall receipt is BLOCKED—not
  failed—because this Windows host has no `cc` for the C-header harness and
  cannot execute the Linux-only live-denial and C-ABI link/run gates.
- BGP support-matrix contract tests: 4 passed.

The first GitHub run for the preceding published tree also exposed a Windows
status-endpoint race: a transient `PermissionError` while reading a worker's
`state.json` was reported as an authorization 403. The repair adds bounded
state-read retries and a redacted 503 for persistent local access
failure, while preserving 403 for actual token, Host, and Origin denials. Nine
focused HTTP tests cover the status and job-list consumers, bounded exhaustion,
redaction, and preserved authorization behavior. The full 202-test Python suite
passes. Published candidate commit `8ff367591d66045ea1a0172a5c0e516b88fe592e`
passed both exact-commit GitHub Actions workflows: native validation #62 and
streaming evidence contracts #58. All six Ubuntu, Windows, and macOS jobs
passed, including the Windows contract job that exposed the race.

The same receipt records sustained fuzzing, representative large-capture
benchmarking, full browser-to-native exercise, and normative protocol
qualification as NOT RUN/NOT ESTABLISHED; automatic full-history TCP remains
unimplemented. Exact-commit CI above covers the implementation-code candidate
`8ff367591d66045ea1a0172a5c0e516b88fe592e`. Documentation-only refresh commit
`3f0680c4c2188714e58ebed498ab11022cbd0d6f` also passed native validation #63
and streaming evidence contracts #59, without changing implementation or test
files. Neither local nor CI results establish lawful real-corpus parity,
scale or performance targets, security qualification, external-source
authenticity, or complete normative protocol conformance. Passing these gates
is not a production-readiness claim.

## Remaining work and priority

1. Close the assembled-source PR feedback test and integration gates with the exact
   source inventory and outcomes in the [round-two feedback receipt](../../evidence/pr-feedback-round2-validation.json).
   A pending or partial receipt does not establish a final validation pass.
2. Complete independent RFC/IANA review and broader executable coverage for
   every declared BGP profile row. Registration and typed parsing do not by
   themselves establish full semantic support.
3. Retain sustained stateful fuzzing and lawful capture/collector disagreement
   evidence, adjudicated from original bytes and primary specifications.
4. Measure representative scale, memory, and throughput; obtain fresh exact-head
   Windows/Linux CI (and macOS where claimed), plus security review, before
   raising the corresponding qualification claims.
5. Continue the separate DNP3 non-secure profile toward its documented
   completion criteria; secure authentication, device truth, and unsupported
   vendor semantics remain outside current proof.

## Boundaries

All parser, replay, policy, and association output is offline evidence or
candidate analysis. No source authenticity, endpoint negotiation, route
installation, reachability, causality, or attack attribution is claimed.
