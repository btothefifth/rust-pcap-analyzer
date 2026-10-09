# Offline BGP session, Adj-RIB-In candidate, and policy slice

This is the directly owning contract for the offline session observer,
Adj-RIB-In reducer, and policy evaluator. Their source identities and caller
configuration remain evidence labels; they do not authenticate a capture or
router. Captured, MRT, and BMP adapters preserve these boundaries when they
prepare or replay source events. Native route-origin references are additive
metadata and do not change default route semantics or endpoint authority.

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

`AdjRibIn::apply` prepares only route entries that the event can mutate, then
publishes the complete record after exact event/action, version, active-entry,
logical-retention, output-proxy and cumulative-work admission. A multi-action
record can target one key repeatedly; all actions share one private stage and
publish atomically. Resets require the same explicit advancing predecessor and
retain old history. A generation-wide gap, stale/EOR marker, peer mismatch or
record conflict may inspect the entry map and stage matching entries; it never
clones unrelated event history. Ordinary current directed UPDATEs use key
lookups and stage only their affected entries.

Exact event replay selects the session/record-label bucket and compares complete
`RibEvent` values, including scope, ordered actions and JSON. Index membership or
a hash alone does not establish equality. Every retained alternative remains
replayable, including historical or conflicting events. A separate gap index
covers session plus generation; peer binding inventories all retained
route-scoped events, including missing-scope and historical records.

Retention uses deterministic typed logical units instead of `Debug` strings:
an owned text charges `32 + 6 * UTF-8-byte-count`; a structural object or map/set
node charges 256; a child sequence container charges 64, a sequence slot 32,
and each scalar identity allowance 8. JSON recursively charges its typed nodes,
text keys/values and slots without rendering. Every duplicated route key,
entry, version, witness, journal event, marker, rejection, generation, taint and
private-index value is charged. Empty top-level containers have zero content
charge. The read-only legacy projection charges its typed entries plus the
existing immutable snapshot's own retained charge once at construction.

`accounted_work()` is cumulative admitted conservative work. It adds three
incoming-event charges (validation, traversal and equality setup), two charges
for prospective private-index growth, two charges for each staged existing
entry (copy plus traversal), a typed-key charge for each entry inspected by a
wide control, and two charges for the incoming mutation bound. The mutation
bound includes prospective generation/taint/gap nodes and, per action, all
possible new entry/version/witness or rejection content. Each indexed equality
candidate adds the incoming and retained event charges. Work and necessary
retained growth are checked before cloning affected entry content; exact final
retention/output and element counts are checked before publication. Overflow
rejects admission. Rejection and inert identical replay preserve both counters and
public state; replay comparison work has a per-attempt bound without consuming
admitted work. Replay consumers charge the checked difference between the
counter before and after their operation, rather than repeatedly adding the
whole cumulative value. Default limits are unchanged.

The private prepared API binds a plan to its reducer instance and append-only
revision. Enclosing pipeline transactions check every plan and budget before
their first publication. Commit contains no Result-returning operation; append
vector replacement capacity is reserved during preparation and old event
objects move only on amortized capacity growth. Standard Rust map insertion may
still abort on allocator exhaustion. Logical charged units do not establish an
allocator quota, persisted encoding size, or RSS bound. Diagnostic counters
report admitted staged-entry copies, indexed equality comparisons, wide entry
visits, copied/measured versions and witnesses, committed entry inserts, deep
journal-event copies and shallow capacity-growth event moves. Standard map
updates insert individual staged members; they never append/rebuild the
canonical map. Rejection/inert replay leave diagnostics unchanged. A repeatedly
updated single key still copies that affected entry's growing versions and
witnesses; that cost is prospectively charged and remains an explicit limit.

Finite regression cases cover typed exact/one-below admission, multi-action
rollback, old alternatives, historical conflicts and 200 ordinary updates.
These cases establish a bounded implementation improvement only. Full scale,
peak RSS and corpus qualification remain open. Policy evaluation still bounds
candidate counts, pair comparisons and the complete output trace under its
existing separate accounting contract. Session-observer and enclosing
pipeline accounting are distinct owners with their own source/evidence.

The direct hand-built tests are
`product/tests/bgp_session_rib_policy.rs`; the atomic captured join is covered by
`product/tests/bgp_pipeline.rs` and [BGP_PIPELINE.md](BGP_PIPELINE.md). They do
not prove persisted replay, MRT/BMP ingestion, independent router policy
equivalence, Linux/fuzz/corpus/scale qualification, or endpoint truth. Those
remain separate contract phases.


Native version occurrence evidence is additive and explicit. `apply_with_origin`
and the prepared equivalent accept the digest of a checked normalized
Observation. Adapters must preserve the full Update action sequence, including
withdrawals and rejects, so each zero-based route ordinal identifies its
original normalized route. The reducer stamps `NativeVersionOccurrence`
(event index, 32-byte observation digest, route ordinal) at each actual Announce
append or coalesce, including conflicting versions. Generic `apply` and legacy
projection leave occurrences empty. No label, attribute match, source ordering
or timestamp recovers this evidence later. Existing default native JSON remains
unchanged; `NativeVersionOccurrence::json()` is an explicit helper for opt-in
consumers, with `event_index`, `observation_sha256` (64 lowercase hexadecimal
characters) and `route_index`.

An internal event-index binding inventory records the actual key, stable
version index and route ordinal even for manual Announce input. An exact full
native-event replay with a distinct checked observation digest appends its proof
to those original bound versions, preserving currency, status, witnesses and
the event journal. The same event plus digest is inert. Historical versions and
versions quarantined by later record collisions retain their bindings. A replay
whose original event produced no announced version has no occurrence to attach.
Origin-only replay plans publish their admitted evidence delta even though their
status remains `IdenticalReplay`; consumers must still commit the plan and charge
the checked work delta. The owner/revision check includes cumulative work, so
such a metadata publication invalidates earlier prepared plans.

Each version's occurrence container charges 64 units, including an empty one;
each occurrence charges 336 (node 256 + two scalar ordinals 16 + digest 32 +
sequence slot 32). Each binding map header charges 328 (node 256 + event ordinal 8
+ container 64), and each binding charges 304 plus its duplicated typed route
key (node 256 + two ordinals 16 + slot 32). Each exact event/digest inventory member
charges 296 (node 256 + event ordinal 8 + digest 32). Work prospectively charges all
new binding/proof content twice as part of the mutation bound. Origin replay
charges indexed full-event equality, each selected binding visit, both copy and
measurement of each affected entry, and twice the new proof/inventory growth.
Bindings, occurrences and proof-inventory members also count toward the existing
element limit; defaults are unchanged. Actual copy/measurement diagnostics include
occurrences and binding traversal. Repeated proof growth on one version still
requires copying its affected entry and is admitted against the cumulative budget.

The independent literal full-route oracle uses one-byte source/partition/session,
record and attribute identities, a Null attribute value and 0.0.0.0/0. Its first
origin-aware event charges 13374 retained units and 34428 work units. A distinct
origin on exact replay charges 632 additional retained units and 25464 additional
work units, without another event or witness. Exact limits and each one-below
limit test atomic rollback, including the proof inventories. Separate finite
cases cover same-label equal-attribute conflicts, duplicate action ordinals,
manual-origin unavailability, coalescing and replay after explicit reset. These
are local finite evidence requirements, not endpoint authority or full scale/RSS
qualification.


## Prepared-event continuity effects

`PreparedRibEvent::continuity_effect()` returns an optional borrowed
`NativeContinuityRef` for a newly staged native transition. It carries the
native scope, status, reason, continuity kind and affected-scope effect without
copying retained history. `continuity_affects_scope` is the shared allocation-
free matcher. Adapters may retain an owned source-event copy only after their
own admission, and publish it with the enclosing prepared transaction.

| Native transition | Affected candidate scope |
| --- | --- |
| Explicit Gap | Same source partition, session, and generation; reported direction and peer do not narrow it |
| New record-identity collision | Same source partition and session across all generations |
| Peer-binding mismatch | Same source partition, session, generation, and direction; peer does not narrow it |
| Accepted Reset | Exact predecessor generation; the effect also identifies the next generation |

Exact event replay, origin-only replay, historical input, already-tainted no-ops,
directionless missing scope, and ordinary Update/Stale/EOR events yield no new
continuity effect. Consumers therefore cannot manufacture a fresh barrier from
a status label or replay an old one. This seam reports finite reducer evidence;
it does not establish actual speaker/router FSM state, source authenticity, or
full scale/RSS qualification.

Embedded projection output has a distinct owner boundary. Standalone
`AdjRibIn::new(Limits)` preserves its typed logical-state output ceiling and
literal exact/one-below accounting contract. Captured pipeline, BMP archive and
MRT archive adapters use the crate-visible `for_embedded_projection` constructor
because their public output quota measures their actual serialized receipt or
archive. It validates the original configuration first, including a nonzero
public output cap, and sets only the internal native logical output ceiling to
`min(caller.retained_bytes, Limits::default().output_bytes)`. This preserves the
8 MiB native default ceiling, honors smaller retained caps, and leaves native
input, work, element and active caps unchanged. It does not raise defaults or
remove native logical admission.

The caller retains its original Limits for actual encoded-output admission and
publication. Exact actual-output acceptance and one-below refusal remain the
encoder/store owner's obligation. Private native indexes and occurrence proofs
therefore cannot be mistaken for emitted output bytes. The constructor's finite
controls preserve the 5026/13086 literal Gap charges with a smaller valid public
output cap; lower retained/work/element caps still refuse atomically, invalid
original configuration is rejected, and the native default ceiling remains.
Standalone typed charge tests are unchanged. Whole archive/receipt qualification
still belongs to its owning adapter gates and assembled review.
