# BGP completion contract

Status: current offline BGP product contract. The support matrix records
declared profile areas and owning code/tests. The [follow-up receipt](../../evidence/pr-followup-validation.json)
records source identity, inventory, local gate results, coherence outcome,
bounded sample scope, and validation status. Consult it for current disposition;
this contract makes no independent pass claim. The `8aa92ad` receipt remains
the historical baseline listed in [VALIDATION.md](../VALIDATION.md); local,
hosted, and broader qualification scopes remain separate.

## Responsibility

This document owns the dependency order, acceptance criteria, and qualification
boundary for completing BGP support in the offline PCAP evidence platform. The
existing producer, import, candidate-state, replay, and association contracts
remain the code-driving leaves for their respective APIs. Where an older leaf
describes a problem already repaired in a later accepted slice, this contract
and current code/tests govern current status. Treat any conflicting older leaf as
historical until its owning contract and code have been reconciled.

The [current implementation pointer](../implementation/CURRENT.md) identifies
the follow-up scope and receipt. Its exact source generation and final
results are read from the receipt, not inferred from this contract.
Older objective and slice summaries remain historical where they differ from the
current code, tests, or owning contracts.

## Outcome and completion definition

The target is a **full declared offline BGP evidence profile**, not a claim that
every past, experimental, vendor-private, encrypted, or future extension is
semantically understood. Completion requires all of the following:

1. Core BGP-4 messages are framed and decoded from segmented/coalesced TCP
   evidence without reading outside declared message or stream boundaries.
2. The declared extension profile below is decoded with capability-dependent
   grammar, exact provenance, deterministic output, bounded resources, and
   explicit malformed/error dispositions.
3. Unknown or out-of-profile messages, capabilities, attributes, AFI/SAFI
   values, and substructures remain source-bound opaque evidence; they are never
   silently discarded, guessed, or treated as supported semantics.
4. Session observations retain both directions, negotiate only when bilateral
   evidence permits it, and preserve ambiguity for partial/asymmetric captures.
5. Candidate route state, Adj-RIB-In, Loc-RIB/best-path policy, and endpoint
   truth are distinct types and schemas. Offline policy results are explained
   candidates, never proof that a router installed or propagated a route.
6. Captured and imported route-collector evidence normalize into the same route
   evidence model while retaining immutable source-kind, partition, clock,
   checkpoint, and trust boundaries.
7. The normal CLI/product path can emit, persist, replay, query, and associate
   the resulting evidence. Every budget cut, gap, reset, conflict, quarantine,
   unsupported value, and incomplete coverage state remains observable.
8. The complete declared profile passes its required local gates and retains
   evidence for every platform and qualification dimension actually claimed;
   normative, fuzz, real-corpus, scale, and independent-oracle conclusions each
   require their own source-bound evidence.

## Non-goals and authority boundary

- No external analyzer, route collector, hash, or successful parse is truth by
  itself. Other implementations are disagreement probes, not normative oracles.
- The parser does not establish reachability, causality, attack attribution,
  source authenticity, router configuration, forwarding behavior, or route
  installation without separate evidence. Source-ordered offline event/FSM
  observations may be reported with their provenance; they do not establish the
  actual state of a speaker or router.
- Automatic GR/LLGR expiry from the host wall clock is outside this offline
  profile. A future caller-clocked timer assessment is design pending and must
  carry its clock basis and provenance, expose source-clock uncertainty as its
  own evidence field, and keep that uncertainty separate from broader
  qualification status.
- BGPsec signature validation, decryption, active peering, packet injection,
  router mutation, and live route control are outside this offline profile.
- Specialized AFI/SAFI payloads and attributes not listed in the semantic
  profile must still be safely framed and retained as opaque evidence.
- The work may extend public schemas only through explicit versioning or
  compatible additive fields; existing evidence must not be silently rehashed
  as if a newer decoder produced it.

## Declared semantic profile

Primary authority is the applicable RFC text and current IANA registries. The
minimum profile is:

| Surface | Required semantic coverage |
| --- | --- |
| Core | BGP-4 header, OPEN with RFC 6286 four-octet unsigned nonzero Identifier semantics, UPDATE, NOTIFICATION, KEEPALIVE, ROUTE-REFRESH, source-scoped finite-state observations, RFC 7606-style UPDATE error dispositions |
| Capabilities | multiprotocol, route refresh, enhanced route refresh, four-octet ASN, graceful restart, long-lived graceful restart, ADD-PATH, extended messages, extended OPEN optional parameters, role; unknown capabilities retained |
| NLRI | IPv4 and IPv6 unicast/multicast, capability-dependent ADD-PATH path identifiers, MP_REACH/MP_UNREACH next-hop and end-of-RIB evidence; unsupported AFI/SAFI payload retained without guessed prefix semantics |
| Core attributes | ORIGIN, AS_PATH, NEXT_HOP, MED, LOCAL_PREF, ATOMIC_AGGREGATE, AGGREGATOR, COMMUNITIES |
| Common extensions | ORIGINATOR_ID, CLUSTER_LIST, MP_REACH_NLRI, MP_UNREACH_NLRI, EXTENDED_COMMUNITIES, AS4_PATH, AS4_AGGREGATOR, AIGP, LARGE_COMMUNITY, OTC |
| AS semantics | two/four-octet layouts, AS_TRANS, AS4 reconstruction, confederation segment syntax, AS0 disposition, duplicate/conflicting alternatives |
| Refresh/restart | normal/enhanced route refresh markers, graceful-restart families/flags/timers, LLGR tuples, stale/EOR evidence without invented wall-clock expiry |
| Route state | per source/session/generation/direction/peer/AFI/SAFI/path-id Adj-RIB-In candidates, withdrawals, replacements, EOR/reset/stale transitions |
| Policy | deterministic, configurable best-path candidate evaluation with a complete ordered decision trace and unresolved result when required inputs are absent/ambiguous |
| External input | bounded MRT TABLE_DUMP_V2/BGP4MP and BMP v1 adapters; source record identity, peer context, clocks, checkpoint, source bytes/hash, and unsupported or malformed records remain explicit. BMP Route Monitoring is a reported, state-compressed view, not a verbatim endpoint UPDATE history. |

Supporting additional AFI/SAFI families or attributes means adding their own
semantic contract and independent fixtures; registering a numeric code is not
semantic support.

## Objective criteria scorecard

| ID | Required outcome | Priority | Acceptance condition | Cheapest falsifier | Owner | Status |
| --- | --- | --- | --- | --- | --- | --- |
| BGP-C01 | Source/provenance conservation | hard | every interpreted value maps to exact captured/imported bytes and immutable source identity | split one field across packets and rebuild its bytes | producer/import adapters | bounded source-bound evidence is recorded by exact generation; completeness and authenticity remain separate |
| BGP-C02 | No false negotiation or authority | hard | unilateral, missing, duplicate, or conflicting OPEN evidence never selects negotiated semantics or route truth | one-sided/conflicting capability vectors | session observer | finite ambiguity controls are scoped to their source generation; endpoint negotiation remains outside offline authority |
| BGP-C03 | Complete declared wire profile | hard | every profile row has valid, boundary, malformed, duplicate, and unsupported-neighbor tests | delete one profile matrix row/test link | wire decoder | open |
| BGP-C04 | AS4 correctness | hard | NEW/NEW, NEW/OLD, AS_TRANS, AS4_PATH and AS4_AGGREGATOR reconstruction/discard rules match independent vectors | path with longer AS4_PATH than AS_PATH | AS semantic reducer | versioned AS4 reconstruction/discard behavior has finite vector coverage; broader normative coverage remains open |
| BGP-C05 | Attribute conformance | hard | flags, length, multiplicity, mandatory attributes and treat-as-withdraw/discard/session-reset dispositions are explicit | wrong flags or duplicate mandatory attribute | UPDATE validator | typed occurrences, dispositions, and source-bound semantic checks have finite owner coverage; complete profile qualification remains separate |
| BGP-C06 | Stateful replay fidelity | hard | gaps/conflicts/resets/reordered records never manufacture continuous session or current route state | changed historical record after reset | session/RIB/replay | source-scoped replay boundaries have owner controls; final-generation outcomes are recorded in the [follow-up receipt](../../evidence/pr-followup-validation.json). Richer finite-state observation remains open, while actual endpoint/router FSM state is outside this offline profile |
| BGP-C07 | Explainable route policy | hard | every selected/unresolved candidate has deterministic ordered reasons and all alternatives remain available | equal candidates differing at final tie-break | policy engine | bounded persisted policy and ordered traces have finite owner coverage; independent full-policy qualification remains separate |
| BGP-C08 | Cross-source normalization without collapse | hard | capture, MRT, BMP and future adapters share route semantics but cannot merge source partitions implicitly | same route bytes from two sources | import/adapters | versioned semantic identity and persisted source-scoped joins cover the supported capture/MRT/BGP4MP/BMP subset; broader cross-source qualification remains separate |
| BGP-C09 | Bounded atomic publication | hard | every public operation fails without partial state/output under each lower budget | one-below output/work/retained budget | every producer/consumer | bounded and atomic producer/consumer paths have owner-specific exact/one-below controls; final-generation outcomes are recorded in the [follow-up receipt](../../evidence/pr-followup-validation.json) |
| BGP-C10 | Operational end-to-end path | hard | CLI capture/import -> evidence -> state -> persisted receipt -> replay/query/association succeeds and exposes cuts | force a boundary between UPDATEs | sink/CLI/history | fresh captured/MRT/BMP replay and persisted query, policy, and association outcomes are recorded in the [follow-up receipt](../../evidence/pr-followup-validation.json); qualification remains separate |
| BGP-C11 | Adversarial and platform qualification | hard for qualified claim | exact-head Linux CI plus separate normative, fuzz, lawful corpus, scale/RSS, and security evidence | exact-head Linux CI or fuzz crash | validation/CI | `8aa92ad` CI is historical; current PR checks are a mutable view and must be tied to their reported SHA. The local follow-up receipt does not establish hosted CI for a later PR head. Normative, fuzz, corpus, CPU/RSS, and broader qualification remain open |
| BGP-C12 | Maintainable extension model | optimization | new opaque capability/attribute requires no decoder rewrite; semantic support is registry-driven and isolated | add synthetic unknown code | typed registries | open |

## Architecture and ownership

```text
TCP evidence / external record bytes
        |
        v
bounded message or adapter framing
        |
        v
wire occurrence evidence  -----> opaque unsupported occurrences
        |
        v
bilateral session observer -----> ambiguity / gap / reset evidence
        |
        v
normalized route events
        |
        +----> ordered replay and immutable receipts
        |
        v
Adj-RIB-In candidate reducer
        |
        v
optional policy evaluator -> Loc-RIB candidate + decision trace
        |
        +----> query/export/association
```

Wire parsing owns byte syntax only. Session observation owns capability and
generation context. RIB reduction owns route replacement/withdrawal state.
Policy owns ranking. Adapters own external container truth and source identity.
No layer may promote a weaker layer's label into endpoint authority.

Ownership follows the evidence path. Raw capture and imported bytes remain in
the source adapters and sealed journals: [captured journal](../../product/src/deep/bgp_store.rs),
[MRT adapter](../../product/src/deep/bgp_mrt.rs), [MRT source store](../../product/src/deep/bgp_mrt_store.rs),
[BMP adapter](../../product/src/deep/bgp_bmp.rs), and [BMP source store](../../product/src/deep/bgp_bmp_store.rs).
Native interpretation and effects belong to the [wire decoder](../../product/src/deep/bgp.rs),
[captured pipeline](../../product/src/deep/bgp_pipeline.rs), [session observer](../../product/src/deep/bgp_session.rs),
and [route reducers](../../product/src/deep/bgp_rib.rs) and [candidate state](../../product/src/deep/bgp_state.rs).

The follow-up shares one bounded scope inventory across change and expectation
analysis in [`bgp_persisted/analysis.rs`](../../product/src/deep/bgp_persisted/analysis.rs).
Its output distinguishes applied native reset/gap effects from source boundaries
or metadata with no route action. [`ImportedSourceEvent::new`](../../product/src/deep/bgp_import.rs)
checks source labels and attached identity while leaving observation and effect
binding to the source producer. MRT archive assembly and persisted replay are
owned by [`bgp_mrt_archive.rs`](../../product/src/deep/bgp_mrt_archive.rs) and
[`bgp_persisted/replay.rs`](../../product/src/deep/bgp_persisted/replay.rs).

[Replay](../../product/src/deep/bgp_replay.rs), persisted consumers, [policy](../../product/src/deep/bgp_policy.rs),
and [association](../../product/src/deep/bgp_association.rs) derive candidate
views from the admitted evidence. Research comparison bundles retain exact
source-range witnesses for a first BGP divergence and a derived-dataset
provenance manifest; see [`bgp_compare.py`](../../tools/research/bgp_compare.py)
and [`bundle.py`](../../tools/research/bundle.py). Bundles remain unresolved
research evidence until adjudicated. The final validation receipt describes the
source generation and checks; it does not replace product source evidence.

Implementation contracts for the external-source, persisted-consumer,
semantic-identity, and profile-evidence seams are maintained in
[MRT ingestion](BGP_MRT.md), [MRT source storage](BGP_MRT_STORE.md),
[BMP ingestion](BGP_BMP.md), [persisted consumers](BGP_PERSISTED.md),
[semantic identity](BGP_SEMANTIC_IDENTITY.md), and
[profile evidence](BGP_PROFILE_EVIDENCE.md). Each leaf defines its own producer,
carrier, consumer, and falsifiers; these links do not imply that its gates have
passed.

## Producer/carrier/consumer proof obligations

| ID | Producer | Carrier | Consumer | Independent oracle | Failure consequence | Required positive join |
| --- | --- | --- | --- | --- | --- | --- |
| BGP-C04 | OPEN + UPDATE bytes | occurrence evidence + session context | AS reconstruction | hand-built RFC vectors | wrong path identity/loop evidence | captured/imported route yields same reconstructed candidate with distinct provenance |
| BGP-C06 | ordered message/import records | session and replay receipts | RIB reducer | state-transition model | stale/resurrected route | reset/withdraw/reannounce replay has exact terminal set |
| BGP-C07 | RIB candidate set + policy config | decision trace | query/association | independent reference evaluator | false winner | every comparison step and unresolved input is visible |
| BGP-C08 | MRT/BMP/capture bytes | normalized schema | replay/RIB/association | container fixture arithmetic | cross-source collapse | equal routes remain source-distinct but semantically comparable |
| BGP-C10 | CLI inputs | persisted evidence/history | replay/query CLI | black-box process test | library-only feature | fresh process reproduces receipt and query result |

## Imported BGP4MP reset and peer-relationship contracts

MRT records replay in file order; timestamps do not reorder session events. A
reset event must match the sealed source/checkpoint currently being replayed and
advance only the matching BGP4MP session generation before any later UPDATE is
reduced. Preserve earlier observations as history; a generation boundary is not
a fabricated per-prefix withdrawal. Keep source/checkpoint/session partitions
distinct through timestamp regressions, ASN metadata enrichment, and multiple
peer sessions in one file. A terminal reset closes only its own peer partition.

The owning source and black-box falsifiers are in
[`product/tests/bgp_mrt_bgp4mp_replay.rs`](../../product/tests/bgp_mrt_bgp4mp_replay.rs):
`imported_generation_boundaries_preserve_order_and_fail_closed_when_missing_or_reversed`,
`terminal_reset_without_notification_closes_only_its_peer_partition`, and
`cli_import_fresh_replay_query_and_export_retain_bgp4mp_events_and_routes`.
These exercise finite imported source evidence; they do not establish actual
endpoint FSM truth or infer teardown withdrawals.

RFC 7606 handling for LOCAL_PREF (attribute 5), ORIGINATOR_ID (9), and
CLUSTER_LIST (10) needs explicit peer-relationship context. Its value is
`internal`, `external`, or `unknown`; default to `unknown`. Do not infer it from
addresses, ASNs, port numbers, record order, or another dissector. Capture
exposes caller configuration, and MRT/BMP replay accepts a caller assertion
that currently applies uniformly to the selected replay. Per-session
relationship maps remain open for mixed-session inputs.

| Relationship / input | Attribute evidence | UPDATE action |
| --- | --- | --- |
| External, valid peer-dependent attribute | Preserve exact occurrence and decoded evidence; mark attribute discarded for external peer | Continue otherwise-valid NLRI actions without using the attribute as accepted route semantics. |
| Internal, valid attribute | Preserve occurrence and accepted typed value | Continue normally. |
| Internal, malformed length for attributes 5/9/10 | Preserve occurrence and validation evidence | Apply treat-as-withdraw to the UPDATE's route actions. |
| Unknown, peer-dependent attribute present | Preserve occurrence and mark relation unresolved | Quarantine dependent route actions; do not guess internal/external. |
| Unknown, no attributes 5/9/10 present | Report unknown context and its provenance | Do not block otherwise-valid independent UPDATE semantics solely due to unused relationship context. |
| Known session reset plus unresolved attribute context | Preserve both observations | Known reset remains effective; unresolved attribute context must not mask it. |

Invalid flags continue through the attribute-flag error policy and are not
excused by external discard. Owning focused source tests include
`product/tests/bgp_attribute_context.rs`,
`product/tests/bgp_phase1.rs::rfc7606_dispositions_control_emitted_route_actions`,
and `product/tests/bgp_producer.rs` for duplicate-occurrence preservation.
These paths identify the proof owners. Exact final outcomes and their source
inventory belong to the [follow-up receipt](../../evidence/pr-followup-validation.json).

## Implementation, design, and proof boundaries

The [support matrix](bgp-support-matrix.json) is the concise profile inventory;
its rows identify source modules and owning tests. Validation outcomes are
recorded in [CURRENT.md](../implementation/CURRENT.md) and the
[follow-up receipt](../../evidence/pr-followup-validation.json).

The product has captured BGP, MRT/BGP4MP, BMP, persisted replay and consumer,
and incremental MRT stream evidence surfaces. Their contracts remain offline:
source identity and clocks are evidence labels; association is not causality or
reachability; route policy is a candidate; and no output proves source
authenticity or router installation.

The following implementation, design, and proof boundaries remain open:

1. **OPEN Identifier value semantics.** The parser applies RFC 6286's
   four-octet unsigned nonzero Identifier rule while retaining dotted display;
   the owner vector covers values previously rejected by the unicast-only
   guard. Complete malformed-message disposition and declared-profile
   qualification remain open. See
   [RFC 6286](https://www.rfc-editor.org/rfc/rfc6286.html#section-2).
2. **Persisted selector coverage.** Typed persisted selectors now cover
   directional prefix containment, origin or path-member ASN, standard/large/
   extended communities, next hop, source/session/partition, generation,
   direction, path-ID state, lifecycle, and caller-reported clock windows.
   `bgp changes` and `bgp expectations` provide source-ordered, caller-scoped
   analysis; unknown clocks, missing boundaries, and incomplete fields remain
   unknown rather than proving absence. Coverage and exact outcomes for the
   follow-up generation are in the receipt.
3. **Persisted evidence projection.** Captured, MRT, and BMP stores retain
   source-specific evidence; full persisted rows expose checked native
   version-origin references and route evidence. The typed contract is in
   [BGP_CAPTURED_CONTINUITY.md](BGP_CAPTURED_CONTINUITY.md). Persisted rows are
   projections of admitted source evidence; they do not establish source
   authenticity or endpoint state.
4. **Reducer accounting and output units.** The accepted observer and
   Adj-RIB-In prepared paths avoid copying unrelated prior history on an
   ordinary append. The RIB path uses affected-entry staging, typed logical
   retention/work charges, and explicit observation-to-route origin metadata.
   A repeatedly updated entry's version/witness history still copies and is
   charged. For embedded reducers, the internal logical-output proxy is capped
   at `min(retained-state limit, 8 MiB default)`; the caller's original limit
   still governs actual archive or pipeline bytes. Exact/one-below outer output
   behavior remains the owning encoder/store's responsibility. These logical
   units do not bound complete byte-copy behavior, allocator use, RSS, CPU, or
   throughput. The final receipt owns scoped sample measurements; full scale
   qualification remains separate.
5. **Offline finite-state observation.** Keep source-scoped transition
   observation open where ordered records support it. This does not grant actual
   speaker/router FSM authority. Caller-clocked GR/LLGR assessment is design
   pending and must carry clock basis and provenance, retain source-clock
   uncertainty as its own evidence field, and keep it separate from broader
   qualification. Host wall-clock expiry is never inferred.

The follow-up receipt records the exact source identity and scoped outcomes;
its status applies only to that generation and does not inherit the historical
`8aa92ad` result. GitHub Actions is Linux-only. The successful root/native,
streaming, and product checks at `8aa92ad` are historical; its runner-acquisition
and 45-minute cancellation attempts are incomplete, not product results. The
mutable [PR checks view](https://github.com/btothefifth/rust-pcap-analyzer/pull/1/checks)
must be checked against its reported SHA before use. Representative
multi-collector/date/corpus parity, normative coverage, sustained fuzzing,
complete byte-copy behavior, whole-process CPU and RSS bounds, and caller-clocked
GR/LLGR assessment remain unqualified.

## Test-design charter

Each semantic feature requires:

- a hand-built valid vector with byte/range arithmetic independent of Rust;
- truncation at every structural boundary;
- malformed length/flag/code and unsupported-neighbor cases;
- duplicate, conflicting, reordered and partial-evidence cases;
- exact output/work/retention limits and atomic one-below failures;
- split/coalesced TCP evidence with exact packet provenance;
- state transition, replay, reset and corruption cases where applicable;
- a real outer-boundary CLI/PCAP or import test; and
- an intentional mutation or equivalent proof that the test can fail.

The cheapest order is pure fixture arithmetic, focused Rust unit/integration,
producer-to-consumer joins, full product/root matrices, release/feature gates,
fuzz/property campaigns, then real corpus and scale. A green downstream test
cannot compensate for a stale fixture rejected by an earlier valid guard.

## Concern register

| Concern | Counterexample | Required rule | Falsifier |
| --- | --- | --- | --- |
| false negotiation | only one OPEN direction advertises four-octet ASN | retain advertisement; negotiated context remains unknown | unilateral OPEN + 2/4-byte ambiguous AS_PATH |
| AS4 information loss | AS4_PATH longer or contains confed segment | apply exact reconstruction/discard rule and retain both originals | independent NEW/OLD vectors |
| duplicate attributes | ordinary ORIGIN or another ordinary path attribute is repeated; MP_REACH/MP_UNREACH is repeated | first ordinary occurrence is the only semantic candidate, subject to its own validation; later instances remain evidence with discard disposition and are not merged; repeated MP_REACH/MP_UNREACH resets the session | equal/conflicting ordinary duplicates, invalid later flags, and repeated MP attribute vectors |
| stale route resurrection | old UPDATE replayed after generation reset | historical evidence remains, effect is not reapplied | reset + old replay + new announce |
| policy overclaim | MED values from different neighboring ASes | configured same-neighbor mode skips MED and continues; a reached unknown input remains unresolved | early decisive path plus two-path pair differing only in MED scope |
| cross-source collapse | capture and MRT records share bytes/hash | source partitions remain immutable | equal route from two sources |
| resource amplification | one UPDATE replicates many large attribute trees | preflight aggregate work/retention before cloning/publication | exact-limit and one-below route fanout |
| formatter/document drift | tests pass while active docs describe repaired defects | current pointer and touched contracts must agree with code | doc consistency check |

## Evidence and history boundary

Earlier objective, slice, and `8aa92ad` receipt narratives remain historical
and retain their original bytes. Validation results stay bound to the source
inventory and environment in each receipt. Read the follow-up receipt's status,
source identity, and results from
[`pr-followup-validation.json`](../../evidence/pr-followup-validation.json), not
inferred from a previous generation.
