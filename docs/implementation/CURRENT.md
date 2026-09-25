# Current implementation pointer

## Objective and authority

Continue the declared offline BGP evidence profile in
[BGP completion](../product/BGP_COMPLETION.md), with RFCs and IANA registries as
normative authority and other analyzers as disagreement probes only. The design
docs remain authoritative for product intent. This pointer is the concise
current-state view; older slice receipts are historical unless cited below.

## Current local slice

The latest audit-fix slice adds a versioned, source-neutral BGP semantic identity
for the supported captured and TABLE_DUMP_V2 route subset; validates supplied
complete identities against the normalized route envelope and retained captured
attribute occurrences; preserves unsupported MRT RIB entries as opaque-only
evidence; and charges their processing/output against bounded budgets before
materialization. Equal fingerprints do not merge sources or establish router
acceptance, installation, or reachability. The controlling details and known
cross-check gaps are in [semantic identity](../product/BGP_SEMANTIC_IDENTITY.md).

The slice also retains the earlier BGP4MP source-ordered candidate replay and
DNP3 source-span/workflow hardening. It does not complete imported BGP4MP
Adj-RIB-In semantics, full DNP3 object/device semantics, or the declared BGP
profile.

## Fresh local validation

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

1. Complete imported BGP4MP session state: apply announcements/withdrawals to
   imported Adj-RIB-In, derive reset/teardown behavior, and retain malformed
   records through archive/replay with exact source ranges.
2. Close semantic identity gaps before claiming full cross-source parity:
   define and test source-bound AS4_PATH/AS4_AGGREGATOR identity; reconcile every
   supported attribute/NLRI row against the matrix. Incomplete routes must stay
   ambiguous rather than acquire a fingerprint.
3. Connect persisted external/captured evidence to common query, policy, and
   association paths while keeping source, clock, checkpoint, and trust
   partitions separate; then implement the bounded BMP adapter.
4. Add independent RFC/IANA vectors, lawful real-capture/collector disagreement
   cases, minimized regressions, and sustained stateful fuzz campaigns.
5. Require fresh exact-commit Windows/Linux CI (and macOS where claimed),
   measured scale/RSS/performance evidence, and security/normative review before
   raising qualification claims.
6. Continue the separate DNP3 non-secure profile toward its documented
   completion criteria; secure authentication, device truth, and unsupported
   vendor semantics remain outside current proof.

## Boundaries

All parser, replay, policy, and association output is offline evidence or
candidate analysis. No source authenticity, endpoint negotiation, route
installation, reachability, causality, or attack attribution is claimed.
