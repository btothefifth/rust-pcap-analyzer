# BGP completion contract

Status: active implementation contract. Baseline:
`21812fa7a9839ccb1eb733d90837ef3463353df6`.

## Responsibility

This document owns the dependency order, acceptance criteria, and qualification
boundary for completing BGP support in the offline PCAP evidence platform. The
existing producer, import, candidate-state, replay, and association contracts
remain the code-driving leaves for their respective APIs. Where an older leaf
describes a problem already repaired in a later accepted slice, this contract
and current code/tests govern current status and the stale leaf must be
reconciled in the same phase that touches it.

BMAD qualification: this program crosses captured wire decoding, capability and
session state, route-state reduction, external-source ingestion, persistent
replay, policy, product output, and independent qualification. A shallow
"support BGP" label would permit implementations that parse fields but invent
negotiation, collapse contradictory evidence, or call a candidate route an
installed route.

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
8. The complete declared profile passes the required local gates and has
   retained cross-platform, fuzz, real-corpus, scale, and independent-oracle
   evidence before the corresponding qualification claim is made.

## Non-goals and authority boundary

- No external analyzer, route collector, hash, or successful parse is truth by
  itself. Other implementations are disagreement probes, not normative oracles.
- The parser does not establish reachability, causality, attack attribution,
  source authenticity, router configuration, forwarding behavior, or route
  installation without separate evidence.
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
| Core | BGP-4 header, OPEN, UPDATE, NOTIFICATION, KEEPALIVE, ROUTE-REFRESH, finite-state observations, RFC 7606-style UPDATE error dispositions |
| Capabilities | multiprotocol, route refresh, enhanced route refresh, four-octet ASN, graceful restart, long-lived graceful restart, ADD-PATH, extended messages, extended OPEN optional parameters, role; unknown capabilities retained |
| NLRI | IPv4 and IPv6 unicast/multicast, capability-dependent ADD-PATH path identifiers, MP_REACH/MP_UNREACH next-hop and end-of-RIB evidence; unsupported AFI/SAFI payload retained without guessed prefix semantics |
| Core attributes | ORIGIN, AS_PATH, NEXT_HOP, MED, LOCAL_PREF, ATOMIC_AGGREGATE, AGGREGATOR, COMMUNITIES |
| Common extensions | ORIGINATOR_ID, CLUSTER_LIST, MP_REACH_NLRI, MP_UNREACH_NLRI, EXTENDED_COMMUNITIES, AS4_PATH, AS4_AGGREGATOR, AIGP, LARGE_COMMUNITY, OTC |
| AS semantics | two/four-octet layouts, AS_TRANS, AS4 reconstruction, confederation segment syntax, AS0 disposition, duplicate/conflicting alternatives |
| Refresh/restart | normal/enhanced route refresh markers, graceful-restart families/flags/timers, LLGR tuples, stale/EOR evidence without invented wall-clock expiry |
| Route state | per source/session/generation/direction/peer/AFI/SAFI/path-id Adj-RIB-In candidates, withdrawals, replacements, EOR/reset/stale transitions |
| Policy | deterministic, configurable best-path candidate evaluation with a complete ordered decision trace and unresolved result when required inputs are absent/ambiguous |
| External input | bounded MRT TABLE_DUMP_V2 and BGP4MP ingestion first; BMP is the next adapter. Original record identity, peer table, timestamps, sequence/checkpoint, source bytes/hash, and unsupported records remain explicit |

Supporting additional AFI/SAFI families or attributes means adding their own
semantic contract and independent fixtures; registering a numeric code is not
semantic support.

## Objective criteria scorecard

| ID | Required outcome | Priority | Acceptance condition | Cheapest falsifier | Owner | Status |
| --- | --- | --- | --- | --- | --- | --- |
| BGP-C01 | Source/provenance conservation | hard | every interpreted value maps to exact captured/imported bytes and immutable source identity | split one field across packets and rebuild its bytes | producer/import adapters | baseline partial |
| BGP-C02 | No false negotiation or authority | hard | unilateral, missing, duplicate, or conflicting OPEN evidence never selects negotiated semantics or route truth | one-sided/conflicting capability vectors | session observer | baseline partial |
| BGP-C03 | Complete declared wire profile | hard | every profile row has valid, boundary, malformed, duplicate, and unsupported-neighbor tests | delete one profile matrix row/test link | wire decoder | open |
| BGP-C04 | AS4 correctness | hard | NEW/NEW, NEW/OLD, AS_TRANS, AS4_PATH and AS4_AGGREGATOR reconstruction/discard rules match independent vectors | path with longer AS4_PATH than AS_PATH | AS semantic reducer | open |
| BGP-C05 | Attribute conformance | hard | flags, length, multiplicity, mandatory attributes and treat-as-withdraw/discard/session-reset dispositions are explicit | wrong flags or duplicate mandatory attribute | UPDATE validator | open |
| BGP-C06 | Stateful replay fidelity | hard | gaps/conflicts/resets/reordered records never manufacture continuous session or current route state | changed historical record after reset | session/RIB/replay | baseline partial |
| BGP-C07 | Explainable route policy | hard | every selected/unresolved candidate has deterministic ordered reasons and all alternatives remain available | equal candidates differing at final tie-break | policy engine | open |
| BGP-C08 | Cross-source normalization without collapse | hard | capture, MRT, BMP and future adapters share route semantics but cannot merge source partitions implicitly | same route bytes from two sources | import/adapters | partial: capture and TABLE_DUMP_V2 emit a shared v1 semantic identity for the supported subset and retain distinct source partitions; imported session Adj-RIB-In, BGP4MP parity, BMP, and persisted semantic joins remain open |
| BGP-C09 | Bounded atomic publication | hard | every public operation fails without partial state/output under each lower budget | one-below output/work/retained budget | every producer/consumer | baseline strong |
| BGP-C10 | Operational end-to-end path | hard | CLI capture/import -> evidence -> state -> persisted receipt -> replay/query/association succeeds and exposes cuts | force a boundary between UPDATEs | sink/CLI/history | open |
| BGP-C11 | Cross-platform and adversarial qualification | hard for qualified claim | Windows/Linux native matrices, macOS compatibility, sustained fuzz, real corpus and scale receipts retained | Linux runner or fuzz crash | validation/CI | open: exact checkpoint `ed4350e` passed native-validation on Windows/Linux/macOS and streaming CI; sustained fuzz, corpus, and scale remain unqualified |
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

## Producer/carrier/consumer proof obligations

| ID | Producer | Carrier | Consumer | Independent oracle | Failure consequence | Required positive join |
| --- | --- | --- | --- | --- | --- | --- |
| BGP-C04 | OPEN + UPDATE bytes | occurrence evidence + session context | AS reconstruction | hand-built RFC vectors | wrong path identity/loop evidence | captured/imported route yields same reconstructed candidate with distinct provenance |
| BGP-C06 | ordered message/import records | session and replay receipts | RIB reducer | state-transition model | stale/resurrected route | reset/withdraw/reannounce replay has exact terminal set |
| BGP-C07 | RIB candidate set + policy config | decision trace | query/association | independent reference evaluator | false winner | every comparison step and unresolved input is visible |
| BGP-C08 | MRT/BMP/capture bytes | normalized schema | replay/RIB/association | container fixture arithmetic | cross-source collapse | equal routes remain source-distinct but semantically comparable |
| BGP-C10 | CLI inputs | persisted evidence/history | replay/query CLI | black-box process test | library-only feature | fresh process reproduces receipt and query result |

## Phases and gates

### Phase 0 — contract and baseline reconciliation

- Make this file the controlling plan and keep `docs/implementation/CURRENT.md`
  thin.
- Reconcile stale BGP leaf findings against current code and receipts.
- Add an executable support matrix linking each profile row to code and tests.
- Establish a rustfmt-clean baseline for the touched BGP surface without an
  unrelated repository-wide rewrite.

Exit: no current document calls a repaired defect open or calls an unqualified
surface complete; baseline focused tests and Clippy pass.

### Phase 1 — wire, capability, AS4, and attribute semantics

- Introduce typed capability and path-attribute occurrence models.
- Implement bilateral capability layout context without claiming endpoint
  negotiation when capture evidence is incomplete.
- Implement declared capability grammars, ADD-PATH NLRI, extended-message and
  extended-OPEN boundaries.
- Implement AS4 reconstruction and complete declared attribute validation/error
  classification while retaining raw occurrences and alternatives.

Exit: BGP-C01 through BGP-C05 and BGP-C09 pass at the direct decoder and real
PCAP depth boundary.

### Phase 2 — session observer and route-state model

- Add an evidence-oriented offline FSM distinct from an active BGP speaker.
- Track generation, bilateral OPENs, negotiated candidate context, EOR,
  refresh, graceful/LLGR stale state, NOTIFICATION and transport boundaries.
- Replace the generic candidate route set with a versioned Adj-RIB-In layer;
  preserve the compatibility adapter until migration tests pass.

Exit: BGP-C02 and BGP-C06 pass through segmented/coalesced TCP, gaps, conflicts,
asymmetric captures, tuple reuse and restart/replay.

#### Imported BGP4MP reset boundaries

The source store replays MRT records strictly in file order. MRT timestamps are
evidence fields and must never reorder session events. For each reset event,
validate that its source ID and checkpoint match the currently replayed sealed
batch, then advance only the matching BGP4MP session contexts by exactly one
generation before any later UPDATE is reduced. Preserve older observations as
history; a generation boundary is not a fabricated per-prefix withdrawal.
Distinct source/checkpoint/session partitions remain distinct, including when
timestamps decrease, ASN metadata is enriched, or multiple peer sessions share
one input file. A terminal reset must close only its own peer partition.

Falsifiers are in
`product/tests/bgp_mrt_bgp4mp_replay.rs`:
`imported_generation_boundaries_preserve_order_and_fail_closed_when_missing_or_reversed`,
`terminal_reset_without_notification_closes_only_its_peer_partition`, and
`cli_import_fresh_replay_query_and_export_retain_bgp4mp_events_and_routes`.
The source store remains external evidence: session reset and candidate
replay do not establish endpoint FSM truth or derive teardown withdrawals.

### Phase 3 — deterministic policy and explainable RIB candidate

- Add a configurable policy profile and deterministic comparison trace.
- Keep local preference/defaults explicit; missing router configuration produces
  unresolved policy, not an invented default winner.
- Expose active, stale, rejected and unresolved candidates separately.

Exit: BGP-C07 passes independent decision vectors and replay invariance tests.

### Phase 4 — external route-collector ingestion

- Implement bounded MRT common header, peer-index table, RIB TABLE_DUMP_V2 and
  BGP4MP/BGP4MP_ET adapters with exact record provenance.
- Implement source-neutral, versioned semantic identity for captured and
  imported routes under [BGP semantic identity](BGP_SEMANTIC_IDENTITY.md).
  Unknown/unsupported/malformed or unresolved values cannot receive a complete
  fingerprint; matching identities must never merge source partitions or
  promote candidate evidence to installed-route truth.
- Add BMP only after MRT and capture normalization share one accepted route-event
  contract.
- Verify source bytes/hash independently; never treat collector labels as
  authentication.

Exit: BGP-C08 passes capture/MRT equivalence and non-collapse tests.

#### Peer-dependent UPDATE attributes

RFC 7606 handling for LOCAL_PREF (attribute 5), ORIGINATOR_ID (9), and
CLUSTER_LIST (10) requires explicit peer relationship context. The context is
`internal`, `external`, or `unknown`; its default is `unknown`, and it must not
be inferred from addresses, ASNs, port numbers, record order, or another
dissector. The capture API exposes explicit `SessionState` configuration. MRT
replay may be given `--peer-relationship unknown|internal|external`; this is a
caller assertion applied uniformly to every BGP4MP session in that replay and
must be supplied again to replay a sealed source store. Use `unknown` for a
mixed or unverified source. Per-session relationship maps are not yet
implemented.

| Relationship / input | Attribute evidence | UPDATE action |
| --- | --- | --- |
| External, valid peer-dependent attribute | Preserve exact occurrence and decoded evidence; mark attribute discarded for external peer | Continue otherwise-valid NLRI actions without using the attribute as accepted route semantics. |
| Internal, valid attribute | Preserve occurrence and accepted typed value | Continue normally. |
| Internal, malformed length for attributes 5/9/10 | Preserve occurrence and validation evidence | Apply treat-as-withdraw to the UPDATE's route actions. |
| Unknown, peer-dependent attribute present | Preserve occurrence and mark relation unresolved | Quarantine dependent route actions; do not guess internal/external. |
| Unknown, no attributes 5/9/10 present | Report unknown context and its provenance | Do not block otherwise-valid independent UPDATE semantics solely due to unused relationship context. |
| Known session reset plus unresolved attribute context | Preserve both observations | Known reset remains effective; unresolved attribute context must not mask it. |

Invalid attribute flags continue through the attribute-flag error policy and
are not excused by external discard. `product/tests/bgp_attribute_context.rs`
contains the relationship matrix, source-evidence, and MRT option tests;
`product/tests/bgp_phase1.rs::rfc7606_dispositions_control_emitted_route_actions`,
`product/tests/bgp_producer.rs::duplicate_path_and_collection_attributes_keep_the_first_value_without_concatenation`,
`product/tests/bgp_attribute_context.rs::ordinary_duplicate_uses_first_effective_value_and_retains_both_occurrences`,
and `product/tests/bgp_attribute_context.rs::duplicate_mp_reach_and_unreach_trigger_session_reset`
cover action aggregation, first-occurrence projection, reset handling, and
evidence retention.

### Phase 5 — product integration and persistence

- Wire session/RIB/replay into the opt-in depth/history path.
- Add CLI import, replay, state, policy, query, and export commands with atomic
  no-overwrite output.
- Persist versioned receipts/checkpoints and surface boundaries, incomplete
  coverage, conflicts and resource cuts in the desktop/query model.

Exit: BGP-C10 passes a fresh-process black-box capture and MRT workflow.

### Phase 6 — qualification and promotion

- Add independent RFC/IANA vectors, property tests, mutations and fuzz targets
  for wire, session, AS4, RIB, policy and adapters.
- Exercise lawful real captures/collector samples and use other analyzers only
  to locate disagreements. Adjudicate from bytes and primary specifications.
- Extend native CI to each promoted BGP gate and retain macOS compatibility;
  exact checkpoint `ed4350e` passed the current Windows/Linux/macOS matrix and
  streaming workflow. Add release/all-feature gates, scale/RSS/throughput and
  restart/corrupt-checkpoint tests.

Exit: BGP-C11 passes for each claim being promoted. Any unrun dimension stays
explicitly unqualified.

### Phase 7 — post-BGP platform order

After the declared BGP profile is complete: full-history TCP/replay; remaining
DNP3 secure/file/endpoint semantics; Modbus TCP/RTU; BACnet; EtherNet/IP/CIP;
IEC 61850 and IEC-104/MMS/ISO/S7; OPC UA; remaining industrial families; then
deeper IT families and packaging. The research comparator becomes a first-class
disagreement and minimization pipeline throughout, but never a truth vote.

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

## Historical checkpoint evidence (not current validation)

At the original baseline, 211 focused Rust BGP tests and 46 independent Python
BGP vectors passed on the Windows host. At the later historical checkpoint, the
then-current worktree passed the
product all-target/all-feature debug and release suites, product no-default
feature tests, warnings-denied product Clippy, product docs, and root/product/
streaming rustfmt. It also passes root debug tests and Clippy, streaming tests,
198 repository Python tool tests (3 platform-conditional skips), and 61
independent BGP vector tests. The new BGP4MP replay suite passes 10/10. Local
results are Windows-host and primarily synthetic. The exact historical
checkpoint `ed4350e` also passed its recorded native and streaming workflows;
those results do not qualify later source revisions.
Neither result establishes sustained fuzz, real-corpus, scale, source
authenticity, endpoint truth, or complete normative qualification.

Phase 0 reconciliation, the bounded MRT adapter, the corrected Phase 1 direct
decoder, and the first session/Adj-RIB-In/policy slice are now locally implemented.
The direct decoder now enforces route-affecting RFC dispositions (including
invalid zero-length known attributes), directional extended-message reception,
bilateral MP family context, valid unicast BGP identifiers, and ADD-PATH route
keys.
The new captured-session pipeline atomically joins decoded messages to the
session observer and Adj-RIB-In, including EOR, NOTIFICATION, RFC session-reset,
gap, explicit transport reset, multi-NLRI and immutable-identity quarantine.
The bounded multi-session manager is now connected to the reconstructed-TCP
`pcap-depth` path and emits source-event-derived receipts and flow-end summaries.
Its bidirectional input preserves TCP sequence order inside each direction and
merges completed protocol events by capture-record evidence order, preventing a
later UPDATE from being applied before an earlier opposite-direction OPEN.
The RIB reducer groups
all route actions from one immutable record atomically, keeps record-identity
quarantine across generations, enforces peer binding, and stops policy
comparison at the first decisive criterion. The state is present in the normal
`pcap-depth` output path. Successful runs now also publish a sealed source-record
journal bound to the complete capture hash; a fresh process verifies and replays
exact BGP bytes and packet spans into state, reused-session query, and NDJSON
export outputs without trusting a saved projection.

The sealed MRT source-store path reparses and normalizes TABLE_DUMP_V2 in a
fresh process and exposes directionless collector candidates through the common
state/query/export verbs. The source-ordered BGP4MP slice now also replays
session events, reuses the shared OPEN/UPDATE parser, and emits capability-gated
imported route candidates with exact message provenance; the 10-test focused
suite, product debug/release/no-default matrices, Clippy, docs, root/streaming
checks, Python tool tests, and independent BGP vectors pass locally on Windows.
It remains candidate replay, not imported session Adj-RIB-In: it does not yet
apply announcements/withdrawals into imported session state, derive teardown
withdrawals, or preserve malformed BGP4MP frames through the MRT archive. It
does not prove collector authenticity, endpoint negotiation, or installed
state. Next: finish imported session RIB/reset semantics and malformed-record
retention, prove captured-versus-imported semantic equivalence without merging
source authority, then add persisted policy/cross-source association, BMP, and
sustained fuzz/corpus/scale qualification plus current platform CI for each
future claimed gate. Completion is
recorded only when code, direct consumer, docs, and acceptance evidence all
agree.

## Current local audit-fix slice

The current local integration adds a versioned cross-source semantic identity
for the supported capture and TABLE_DUMP_V2 route subset. The identity excludes
source, timestamp, offset, wire order, and ADD-PATH Path Identifier; communities
use their standardized set semantics; AS_SET/AS_CONFED_SET members are
canonicalized; and incomplete, unresolved, Partial, or unsupported semantics
cannot produce a complete fingerprint. Ordinary duplicate attributes follow
the RFC 7606 first-occurrence rule, while duplicate MP_REACH_NLRI and
MP_UNREACH_NLRI cause session reset. Unsupported MRT RIB entries now appear as
opaque-only source-bound evidence without entering route-candidate state.
The shared state consumer also rejects a complete identity sidecar whose
canonical attribute values disagree with the normalized route envelope; for
captured Large Communities it checks the retained first type-32 occurrence,
while the MRT normalizer emits a separate sorted/deduplicated imported
projection that the consumer checks. Unsupported MRT evidence is sized and
charged against output, retained-byte and work budgets
before attribute hashing/materialization, then streamed item-by-item by the
bounded JSON writer.
Capture and imported observations remain separate even when their semantic
fingerprints match. Details and falsifiers are in
[BGP semantic identity](BGP_SEMANTIC_IDENTITY.md).

This is a focused implementation slice, not completion of BGP-C03/C05/C08 or
the declared full offline profile. BGP4MP does not yet reduce imported UPDATEs
into a complete session Adj-RIB-In, and BMP, persisted policy/cross-source
association, broad profile-driven tests, sustained fuzzing, lawful real-corpus
parity, scale qualification, and fresh exact-commit cross-platform CI remain
open. Local synthetic tests do not establish external-source authenticity,
negotiated endpoint state, installed routes, reachability, or complete normative
conformance. The fresh Windows-only audit-fix validation is recorded in the
[current implementation pointer](../implementation/CURRENT.md) and the dated
[validation receipt](VALIDATION.md); it does not close the remaining profile or
qualification gaps. The repository commit and remote publication identity are
reported separately after publication, not embedded in this source document.
