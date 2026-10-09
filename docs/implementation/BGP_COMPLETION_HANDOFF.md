# BGP completion implementation handoff

This handoff routes implementation and qualification work under the
[BGP_COMPLETION.md](../product/BGP_COMPLETION.md) profile contract. The
[support matrix](../product/bgp-support-matrix.json) names profile areas,
implementation owners, and tests. [CURRENT.md](CURRENT.md) and the root-owned
[`evidence/bgp-profile-review-validation.json`](../../evidence/bgp-profile-review-validation.json)
receipt record executed outcomes against an exact source inventory; local,
hosted, and qualification scopes remain separate.

## Mission and authority boundary

Complete the declared offline BGP evidence profile while keeping each result
source-bound, deterministic, and resource-bounded. Captured packets, MRT and BMP
records can support observations and route candidates; they do not establish
source authenticity, actual endpoint negotiation, router FSM state, installed
routes, reachability, causality, attribution, or live control. A source-clock
label is not a synchronized wall clock.

The repository's current GitHub Actions policy is Linux-only. Earlier Windows or
macOS evidence remains historical to its named source and environment. Do not
report platform, normative, fuzz, real-corpus, scale/RSS, security, or release
qualification without a receipt for the exact source and scope claimed.

## Current implementation surfaces

- **Wire and capture:** bounded framing and typed BGP evidence are present. The
  parser applies RFC 6286's four-octet unsigned nonzero OPEN Identifier rule
  while retaining dotted display. Owner:
  `product/src/deep/bgp/producer.rs`; direct vector:
  `product/tests/bgp_phase1.rs`. Broader malformed-message and profile
  qualification remain separate.
- **MRT/BGP4MP and BMP:** source-ordered import and source-scoped candidate RIB
  paths are present in the current implementation. It does not
  claim a complete actual speaker/router FSM. See `product/src/deep/bgp_mrt_store.rs`,
  `product/src/deep/bgp_bmp_store.rs`, and their owner suites
  `product/tests/bgp_mrt_bgp4mp_replay.rs` and `product/tests/bgp_bmp.rs`.
- **Persisted query and analysis:** typed selectors cover directional prefix
  containment, origin/path-member ASN, standard/large/extended communities, next
  hop, source/session/partition, generation, direction, path-ID state,
  lifecycle, and caller-reported clock windows. `bgp changes` and
  `bgp expectations` provide source-ordered, caller-scoped analysis. The
  observation-event selector suite returned 11 passing finite checks. Captured
  decoded Gap/Reset continuity events bind their decision to verified
  observation and journal occurrences before filtering. Owners:
  `product/src/deep/bgp_persisted/query.rs`,
  `product/src/deep/bgp_persisted/analysis.rs`, and
  `product/src/bin/pcap_depth_support/bgp_query_selectors.rs`; tests:
  `product/tests/bgp_persisted_selectors.rs` and
  `product/tests/bgp_persisted_analysis.rs`.
- **Persisted evidence:** source stores preserve their source-specific evidence,
  and persisted rows expose checked native version-origin references and route
  evidence. The 12-case persisted-evidence owner suite returned 12 passing finite
  checks, including captured continuity. See
  `docs/product/BGP_CAPTURED_CONTINUITY.md`,
  `docs/product/BGP_PERSISTED_EVIDENCE.md`, and owners under
  `product/src/deep/bgp_persisted/` plus `product/src/deep/bgp_evidence.rs`.
  Digests and labels do not authenticate a source.
- **Peer relationship scope:** MRT/BMP replay relationship context is a caller
  assertion applied uniformly to the selected replay. Per-session maps remain
  open for mixed-session input; do not infer peer class from addresses, ASNs,
  record order, or another dissector. Preserve `unknown` when context is absent.
- **Stream evidence:** incremental MRT admission, source-order chronology,
  explicit ASN/time-window selectors, evidence manifests, and attributed
  comparison form a distinct product surface. See
  [BGP_STREAM_EVIDENCE.md](../product/BGP_STREAM_EVIDENCE.md) and matrix row
  `BGP-S013`; this path is not a general captured/MRT/BMP persisted query.
- **State accounting:** observer and Adj-RIB-In prepared paths append ordinary
  events without copying unrelated prior history. RIB admission stages affected
  route entries, uses typed logical charges, and retains explicit observation
  digest/route-ordinal origin references. Repeated updates to one entry still
  copy and measure its growing version/witness history. Embedded reducers use a
  logical output proxy capped at `min(retained-state limit, 8 MiB default)`;
  each outer owner continues to enforce the caller's original cap against
  actual encoded bytes. Logical admission does not bound allocator use, OOM,
  RSS, CPU, or throughput. Owners: `product/src/deep/bgp_rib.rs`,
  `product/src/deep/bgp_session.rs`, `product/src/deep/bgp_pipeline.rs`; tests:
  `product/tests/bgp_session_rib_policy.rs` and
  `product/tests/bgp_pipeline.rs`.

## Bounded next work

1. Preserve captured decoded Gap/Reset continuity through verified sealed replay
   and process it at its source ordinal before analysis filters. The owner
   controls include an opaque-NLRI UPDATE between announcements, conditional
   absence, EOR/valid-empty controls, and source/session/lifecycle isolation.
2. Keep full-profile persisted evidence projection aligned, including exact
   occurrence references and native route-origin fields; keep digests separate
   from source authentication.
3. Record exact and one-below embedded logical-output proxy and caller encoded-
   output outcomes against the frozen source inventory.
4. Keep reachable per-operation controls, exact-generation observer/pipeline
   checks, and repeated-version history charges explicit. Measure allocation
   and RSS separately from logical admission; do not infer OOM, CPU, or
   throughput guarantees.
5. Keep richer source-scoped FSM observation open where input records support
   it. Actual router FSM remains outside offline authority. Caller-reported
   GR/LLGR timer assessment is design pending and must state clock basis and
   provenance, retain source-clock uncertainty as a separate evidence field, and
   keep it distinct from broader qualification; never infer expiry from host
   wall time or a missing event.
6. Close declared profile and qualification rows independently. Use primary
   RFC/IANA material, independent fixtures, exact-generation local/hosted proof,
   sustained fuzzing, lawful real-corpus evidence, and measured scale only for
   claims those receipts actually establish.

## Review traps

- Do not deserialize a saved route projection as replay authority.
- Do not turn TABLE_DUMP candidates into captured-direction state.
- Do not reorder source records by timestamps or combine independent clocks.
- Do not treat BGP4MP direction or ADD-PATH subtype as bilateral negotiation.
- Do not fabricate packet spans for MRT/BMP sources.
- Do not infer router configuration, actual endpoint FSM, installation, or
  source authenticity from parsed evidence or hashes.
- Do not merge source partitions because route keys or bytes match.
- Do not exceed resource limits by silently evicting evidence or estimates.
- Do not call synthetic tests real-corpus, sustained fuzz, scale, security,
  endpoint, or normative qualification.

## First action after takeover

Read this handoff, the current BGP completion contract and matrix, then the
implementation pointer and each receipt it cites. Verify the exact source
inventory and active Linux-only CI results before choosing an implementation
boundary. Historical receipt prose is not proof for a newer generation. Keep
source changes, focused tests, independent review, and exact-head validation
separate; this handoff revision itself closes no code or qualification gate.
