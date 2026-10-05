# Current implementation pointer

This pointer identifies the current BGP implementation surfaces and their
validation route. The planned root-owned receipt will record executed outcomes and exact source
inventory; local, hosted, and qualification scopes remain separate.

## Active BGP surfaces

The implementation has these declared offline product surfaces:

- Bounded captured BGP framing, normalized observations, and packet-span
  provenance.
- MRT/TABLE_DUMP_V2/BGP4MP and BMP import, source identity, fresh replay, and
  source-scoped route candidates.
- Persisted replay, state, typed query selectors, source-ordered change and
  caller-scoped expectation analysis, policy, export, and association consumers
  for supported captured/MRT/BMP stores. The observation-event selector owner
  suite returned 11 passing finite checks. Captured decoded Gap/Reset events
  bind their native decision to verified observation and journal occurrences
  before source-ordered analysis.
- Incremental MRT source admission, chronology, explicit ASN/time-window
  selection, evidence manifests, and bounded attributed external comparison;
  see [BGP_STREAM_EVIDENCE.md](../product/BGP_STREAM_EVIDENCE.md) and
  [matrix row BGP-S013](../product/bgp-support-matrix.json).

- Persisted evidence rows expose checked native version-origin references and
  route evidence. The 12-case persisted-evidence owner suite returned 12 passing
  finite checks, including the captured-continuity extension. Details are in
  [BGP_CAPTURED_CONTINUITY.md](../product/BGP_CAPTURED_CONTINUITY.md) and
  [BGP_PERSISTED_EVIDENCE.md](../product/BGP_PERSISTED_EVIDENCE.md).
- Observer and Adj-RIB-In prepared paths use bounded staged admission and typed
  logical accounting. Embedded reducers use a separate logical-output proxy;
  each outer owner retains the caller's actual encoded-output limit.
- Incremental stream evidence includes the optional native/Python per-field
  action/prefix comparison bridge.

These surfaces produce offline observations and candidates. They do not prove
source authenticity, endpoint negotiation, actual router FSM state, route
installation, reachability, causality, or attribution. A generation boundary
preserves history; it does not invent per-prefix withdrawals.

## Implementation, design, and proof boundaries

- OPEN Identifier parsing uses RFC 6286 four-octet unsigned nonzero semantics,
  including values previously rejected by the unicast-only guard. Broader core
  malformed-message disposition and profile qualification remain separate.
- Typed persisted selectors cover directional prefix containment,
  origin/path-member ASN, standard/large/extended communities, next hop,
  source/session/partition, generation, direction, path-ID state, lifecycle,
  and caller-reported clock windows. `bgp changes` and `bgp expectations` are
  source-ordered and caller-scoped. The observation-event selector owner suite
  returned 11 passing finite checks. Captured decoded Gap/Reset events bind the
  typed decision to the exact verified observation and journal occurrence
  before analysis. Unknown times, incomplete fields, and missing boundaries
  stay unknown.
- Persisted evidence rows expose checked native version-origin references and
  route evidence; the 12-case persisted-evidence owner suite returned 12 passing
  finite checks. A digest or caller label does not authenticate the source.
- The observer appends ordinary events without copying prior history. The
  Adj-RIB-In reducer stages only affected entries and uses typed logical charges
  and explicit route-origin references. Repeated updates to one key still copy
  and measure its growing version/witness history. Embedded logical output is
  capped by `min(retained-state limit, 8 MiB default)` while each outer owner
  applies its original cap to actual encoded output. Logical admission does not
  bound allocator use, OOM, RSS, CPU, or throughput; exact output outcomes are
  recorded by the source-bound receipt.
- Richer source-scoped finite-state observation remains open. Caller-reported
  GR/LLGR timer assessment is design pending and requires clock basis and
  provenance, with source-clock uncertainty kept as its own evidence field and
  separated from broader qualification. No host wall-clock expiry or actual
  router state is inferred.

The [BGP support matrix](../product/bgp-support-matrix.json) links each profile
area to its owning source modules and tests. `accepted_local` or `partial` rows
are bounded local profile statuses, not full qualification claims.

## Validation and qualification status

GitHub Actions is Linux-only by repository-owner direction. Windows/macOS
receipts, if present for older revisions, remain historical and do not imply
continuing non-Linux CI. The support-matrix test pins the `usage().detail`
selector text from `product/src/bin/pcap-depth.rs` by SHA-256; it is static and
does not execute the native CLI. Paired finite owner runs returned 32 analysis,
12 persisted-evidence, 37 pipeline, and 42 replay checks (123 total, with zero
failed or ignored); four additional admission-unit tests passed separately.
Other bounded outcomes include 37 session/RIB checks, 73 vector checks, 66
Python comparison checks plus one native comparison bridge check, and a 13-check
source-inventory frontier after the vector census was corrected to 11 modules
and 73 tests. These results do not constitute the full product gate. The
standalone 11-case selector result does not by itself establish complete source
coverage; the current captured-continuity extension is covered by the paired
suites. The root-owned
[evidence/bgp-profile-review-validation.json](../../evidence/bgp-profile-review-validation.json)
receipt will record executed outcomes and exact source inventory; local, hosted,
and qualification scopes remain separate.

Normative completeness, sustained fuzzing, lawful real-corpus
parity/differential minimization, representative scale/RSS, security review, and
any manual Windows/macOS claim each require separate evidence bound to the
source and scope claimed. Integrity digests, synthetic tests, external-analyzer agreement, or a partial
local profile status do not supply those qualifications.
