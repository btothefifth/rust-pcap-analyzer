# Atomic captured BGP session pipeline

`deep::bgp_pipeline::CapturedSessionPipeline` is the first direct Phase 2 join
from one captured BGP message into the existing bounded wire decoder, offline
session observer, and versioned Adj-RIB-In candidate reducer. It is bound at
construction to one 32-byte capture namespace, source label, and caller-assigned
TCP session. In `pcap-depth` the namespace is the independently computed SHA-256
of the complete capture. A content hash is identity, not source authentication.
This is not an active BGP speaker
and does not claim endpoint state.

## Atomic application

`apply_message` validates the bound source/session/capture provenance, decodes
one framed message, validates the normalized observation, derives session and
route events, and prepares every downstream change before publication. For a
unique ordinary current-directed UPDATE or KEEPALIVE, the observer appends its
new event, projection, and record index; it does not copy earlier observer
history. The Adj-RIB-In reducer stages only route entries the event can affect,
uses deterministic typed logical charges, and records optional checked
observation-to-route origin references. A multi-action UPDATE shares one
private stage and publishes atomically. Growth in one key's version and witness
history remains charged because that affected entry must be staged and measured.
The pipeline validates owner revisions and all reducer budgets before its first
publication, so failed preparation leaves wire generation, observer journal,
and RIB journal unchanged.

Rare observer controls use a bounded precharged staged fallback. Explicit
gap/reset methods retain bounded complete-pipeline clone transactions. The planned root-owned receipt will record exact-generation per-operation
outcomes; see
[CURRENT.md](../implementation/CURRENT.md) and
[BGP_SESSION_RIB_POLICY.md](BGP_SESSION_RIB_POLICY.md).

The returned `ApplyReceipt` retains the normalized evidence, its observation
digest, session/RIB dispositions, whether the decoded message established a
protocol reset, and optional `continuity: Option<DecodedContinuity>`. The typed
decision carries scope, reason, native status, session status, and
`newly_applied`; its private Copy native kind/effect are supplied by the
prepared reducer. A bounded immutable-input journal is checked before decoding,
so replaying a reset message cannot reinterpret it in the successor generation.
Cached replay retains the original decision with `newly_applied=false` and does
not reapply the boundary.
Attribute occurrence identity is reduced to a bounded SHA-256 token for the RIB
key while the complete canonical occurrences remain in the normalized
observation.

## Boundaries and ambiguity

- BGP NOTIFICATION and UPDATE errors classified `session_reset` advance the
  decoder and observer by exactly one generation. If the RIB already has the
  predecessor generation, its candidates are superseded by the same record.
- Conventional empty UPDATE and negotiated empty MP_UNREACH are explicit EOR
  events. An opaque or unnegotiated MP family never creates an EOR.
- A transport gap is recorded separately with `observe_gap`; it makes existing
  and later same-generation candidates unresolved, even when it precedes the
  first route, but does not invent a successor generation.
- A source-bound BGP framing issue in a known captured session also records
  loss of interpretation. Its gap remains scoped to that BGP session; other
  protocol observers change only at their own or a transport boundary. Original
  framing evidence remains in the capture event, and its immutable event ID
  links the journal's gap to that evidence. Before the first managed BGP MESSAGE,
  the gap remains pending until that MESSAGE admits the scope; an issue-only
  lifecycle that ends first retains capture evidence without a BGP journal scope.
- A successfully decoded UPDATE can still create a native Gap when an opaque
  NLRI prevents a justified route interpretation. That continuity effect is a
  source event even though the normalized observation has no route withdrawal.
  Sealed replay and analysis preserve the typed effect and its verified capture
  witness; `changes` and `expectations` process it at its source ordinal before
  applying output selectors. EOR and valid empty UPDATE controls do not create a
  decoded Gap or Reset by themselves.
- `reset_generation` requires a distinct caller-observed transport boundary and
  advances all state with the exact predecessor. Exact gap/reset replay is
  inert; a reused boundary identity with changed meaning is quarantined without
  advancing wire state.
- Ambiguous path-attribute context becomes a rejected RIB record rather than an
  active candidate. Treat-as-withdraw actions from the decoder remain
  withdrawals. Session-reset UPDATEs expose no route actions.
- A changed immutable record identity is retained as a conflict and permanently
  taints that pipeline instance. Its changed semantic payload is replaced by a
  RIB gap, so even a record that changes from OPEN to UPDATE cannot install a
  route or advance wire generation before quarantine. Later application
  requires a new source partition instead of silently rehabilitating the state.

Unknown direction remains evidence and cannot form an active route key. Source
labels, peer labels, timing, and capture namespaces are evidence identity, not
source authentication, peer negotiation, route installation, reachability, or
policy truth.

## Current boundary

`deep::bgp_manager::CapturedSessionManager` is the bounded multi-session owner.
It accepts caller-assigned TCP analysis-session IDs, refuses silent active-state
eviction, isolates all pipeline state, and returns typed lifecycle summaries.
It does not infer that a session ID proves a physical connection or endpoint.

`pcap-depth analyze` now uses this manager. The streaming layer reconstructs TCP,
frames BGP messages, and emits gaps/conflicts before messages. It decodes each
direction in TCP sequence order, buffers only bounded plugin events, then merges
completed events according to the latest capture record contributing to their
evidence. This preserves out-of-order TCP reassembly while preventing the old
direction-at-a-time behavior from applying an UPDATE before an earlier
opposite-direction OPEN. This is observed capture ordering, not proof of remote
endpoint execution timing. The depth sink
derives each immutable record ID from the complete source-bound event rather
than raw message bytes, so equal UPDATE bytes at distinct packet/range
occurrences do not collapse. Pre-message gaps are retained, each BGP message
event gains `depth_bgp_pipeline`, and flow-end events gain
`depth_bgp_session_summary`. An unscoped message remains wire evidence but does
not enter managed session state.

A complete message rejected for a non-budget error by the deep decoder retains its original MESSAGE
record and rejection details. The sink applies one continuity gap immediately;
fresh replay derives one gap from the same rejected MESSAGE. No additional
journal GAP is written for this case. Immediate and fresh replay agree about
session summaries and route currency, while their gap witness IDs may reflect
the event and sealed-record carriers respectively. Later evidence in the same
generation cannot restore resolved continuity. No withdrawal or successor
generation is inferred. Preparation, gap-admission and resource-limit failures
propagate to the caller. The ordinary `pcap-depth analyze` path stops on the
error before finishing and publishing the source journal; callers must respect
the EventSink contract that an error stops the producer.

Successful `pcap-depth` runs now also publish a sealed, hash-chained BGP source
journal. It retains exact reconstructed message bytes and all source spans plus
gap, reset, flow-end, and capture-boundary records. Fresh-process replay rejects
unsealed, truncated, trailing, reordered, or changed records and rebuilds the
wire/session/RIB projections rather than trusting a serialized state snapshot.
State, reused-session history query, and NDJSON export are available through the
CLI described in [BGP_STORE.md](BGP_STORE.md).
Flow-end history retains its last observed statuses and witnesses, with
`native_current=false` in persisted rich route rows. An Active historical
status after END does not make that row eligible for current policy selection.

MRT and BMP now have sealed source stores and source-scoped replay, state,
query, policy, export, and association consumers. TABLE_DUMP_V2 remains a
directionless collector candidate. The persisted query supports typed prefix,
route-attribute, scope, lifecycle, and caller-reported time selectors; change
and expectation analysis are separate source-ordered, caller-scoped operations.
The observation-event selector owner suite returned 11 passing finite checks,
and the 12-case persisted evidence owner suite returned 12 passing finite
checks, including the captured decoded-Gap continuity extension. These bounded
results do not establish complete source coverage: verified gap boundaries
reach source-ordered changes and expectations before route and time filters. See
[BGP_PERSISTED_EVIDENCE.md](BGP_PERSISTED_EVIDENCE.md) for version-origin
references, source-event continuity, and output projection boundaries. These
are offline evidence surfaces, not source authentication, router state, or full
qualification.

The decoder, observer, RIB, and immutable-input journal each enforce
conservative logical retention/work limits. Embedded RIB logical output uses a
separate proxy capped at the smaller of retained-state allowance and the native
8 MiB default. The archive or captured-pipeline owner continues to enforce its
caller's original limit against actual encoded output, including its own exact
and one-below behavior. Logical charges do not establish allocator, CPU, RSS, or
throughput bounds; complete scale qualification remains open.

Direct tests are in `product/tests/bgp_pipeline.rs` and cover bilateral OPEN to
active route state, multi-NLRI atomicity, EOR, reset, gap separation,
failure atomicity, and immutable record-identity quarantine. Manager isolation
and lifecycle tests are in `product/tests/bgp_manager.rs`; captured CLI behavior
is exercised by `product/tests/pcap_depth_cli.rs`. Persisted selectors, source
analysis, and evidence projection have owner suites in
`product/tests/bgp_persisted_selectors.rs`,
`product/tests/bgp_persisted_analysis.rs`, and
`product/tests/bgp_persisted_evidence.rs`. These paths identify proof owners; the planned root-owned receipt will record
their executed outcomes and exact source inventory.
