# Offline BGP session, Adj-RIB-In candidate, and policy slice

This is the directly owning contract for the opt-in Phase 2/3 library modules
`bgp_session`, `bgp_rib`, and `bgp_policy`. Their schema labels end in `.v1`.
They do not change `bgp::SessionState`, `bgp_state::CandidateState`, the sink,
CLI, or persisted producer events. Caller-supplied source identities and policy
configuration are assertions, not authentication of a router or capture.

## Session observer

`SessionObserver` is bound to one immutable `SourcePartition` and session. An
event includes an explicitly supplied generation, record ID, optional direction,
and one observed message or boundary. Both directions retain distinct OPEN
alternatives and KEEPALIVE, UPDATE, NOTIFICATION, ROUTE-REFRESH, EOR, graceful
and LLGR stale witnesses. Repeated identical OPEN content accumulates witnesses;
different OPEN content remains an alternative. A bilateral capability context is
only a candidate intersection when each direction has exactly one unambiguous
OPEN. Multiple instances of a capability code are retained and do not by
themselves create ambiguity; the producer must mark malformed or conflicting
occurrences ambiguous. Capability-value identities are validated lowercase
SHA-256 text. Unscoped OPENs, conflicts, gaps, and missing directions leave the
context unresolved. The code-only intersection cannot authorize AFI/SAFI,
ADD-PATH, restart, or other value-dependent grammar. This is not endpoint
negotiation or a speaker FSM.
`SourcePartition::from_import_context` uses the existing validated batch and
checkpoint namespace through a bounded digest; the hash identifies supplied
metadata and does not authenticate its source. Captured partition IDs must be
supplied by the caller.

Only an explicit advancing reset with the current predecessor starts a new
generation in the standalone observer. A plain `Notification` closes the
observed generation without creating a successor. The atomic captured pipeline
may instead submit `ProtocolReset` only after the decoder proves that a
NOTIFICATION or RFC UPDATE error advanced by exactly one generation; the
original message remains the boundary record in the journal. A gap records lost
continuity; later messages in the same generation
stay evidence but cannot repair the context. Explicit EOR removes that direction
and family's stale marker. No hold, graceful, or LLGR timer is inferred or run.
Identical record replay is inert even after reset. A changed record ID payload
is retained and permanently quarantines that source partition and session;
generation reset cannot rehabilitate a broken immutable identity. Imported
generation changes require the exact checked successor. Captured boundaries may
advance by more than one only when the caller explicitly supplies the boundary.

## Adj-RIB-In candidates

`AdjRibIn` accepts every ordered route action from one source record as a single
atomic `Update` event. This allows one UPDATE to withdraw and announce multiple
prefixes without treating its own shared record ID as a collision. It keys
candidates by source kind/partition, session, generation, direction, immutable
optional peer binding, AFI/SAFI, path ID state, and canonical prefix. An
unknown direction has no route key and remains an unscoped journal event. An
unknown path ID or unsupported family is unresolved. Per-key versions retain
duplicate witnesses, replacement attributes, withdrawal, reannouncement, stale,
EOR, and superseded generations. EOR marks unrefreshed stale candidates
`StaleAtEor`; only a fresh announcement makes a candidate active. An explicit
gap makes the generation unresolved. Changed record identity preserves both
occurrences and quarantines all generations of its session. A changed or missing
peer binding cannot create a second key while leaving the first active; the
affected scope becomes unresolved. Old events after reset are historical and
inert; exact replay of any retained alternative is inert. An explicitly rejected record appears in a
separate rejection list and cannot erase an older candidate without a separate
withdrawal event.

`from_candidate_state` is a read-only compatibility adapter. It retains a clone
of the exact original candidate journal, outcomes, alternatives, partitions,
and witnesses. A present ADD-PATH identifier is carried into the Adj-RIB-In key;
an ordinary route is explicitly `Absent`, while only genuinely unavailable legacy
identity is `Unknown`. A legacy snapshot hash is the fallback partition marker
when no import partition exists. The adapter cannot infer missing path IDs, true capture
partition identity, or endpoint route state. To use the new reducer for ongoing
events, replay the original source observations under a caller-established
partition and generation; do not append to the projection.

## Policy

`evaluate` requires a provenance-labeled configuration and an explicit
comparison context. It compares active candidates from one source partition,
direction, prefix, and family. All candidate alternatives remain with the
caller; stale, rejected, and unresolved entries are listed as excluded. The
ordered trace covers local preference, local origination, AS-path length,
origin, MED, eBGP/iBGP, IGP metric, age, router ID, and neighbor address.
Missing local preference uses only an explicitly configured fallback. MED is
compared only under the configured scope; a known absent MED compares as zero,
while unavailable MED evidence remains unknown. Different neighboring AS values
in `SameNeighborAs` mode skip MED and continue to the next criterion. Age is
skipped or compared only when explicitly configured with the same clock ID.
Only inputs reached by the ordered comparison are required. Missing reached inputs,
incomparable address families, ambiguous scope, equality after the last tie
break, or absent configuration return unresolved. Candidate IDs only order the
trace; they never break a route tie. Every pair is compared in deterministic ID
order, so input permutations cannot select different winners. The result
explicitly keeps endpoint RIB and propagation claims false.

## Bounds and proof boundary

`apply` stages a complete clone and publishes only after event, active-entry,
logical retention, output-proxy, and work caps pass. Exact-cap and one-below
failures are tested for session and RIB operations. `evaluate` bounds candidate
count, pair work, and complete trace size. These are conservative logical Rust
structure/debug-representation budgets, not a canonical persisted encoding,
measured CPU, allocator usage, or RSS. Canonical persistence and independent
resource qualification remain Phase 5/6 obligations. The direct hand-built tests are
`product/tests/bgp_session_rib_policy.rs`; the atomic captured join is covered by
`product/tests/bgp_pipeline.rs` and [BGP_PIPELINE.md](BGP_PIPELINE.md). They do
not prove persisted replay, MRT/BMP ingestion, independent router policy
equivalence, Linux/fuzz/corpus/scale qualification, or endpoint truth. Those
remain separate contract phases.
