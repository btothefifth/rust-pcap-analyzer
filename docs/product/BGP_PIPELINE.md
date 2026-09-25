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

`apply_message` validates the bound source/session/capture provenance, clones all
owned state, decodes exactly one framed message, validates the normalized
observation, derives the session and route events, and applies both downstream
reducers. The clone is published only after every step succeeds. A failure in
any stage leaves wire generation, observer journal, and RIB journal unchanged.

The returned `ApplyReceipt` retains the normalized evidence, its observation
digest, session/RIB dispositions, and whether the decoded message established a
protocol reset. It also distinguishes an inert exact replay from an initial
application. A bounded immutable-input journal is checked before decoding, so
replaying a reset message cannot reinterpret it in the successor generation.
An inert replay reports `protocol_reset = false`; its original normalized
message remains available without re-authorizing the transition.
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

Successful `pcap-depth` runs now also publish a sealed, hash-chained BGP source
journal. It retains exact reconstructed message bytes and all source spans plus
gap, reset, flow-end, and capture-boundary records. Fresh-process replay rejects
unsealed, truncated, trailing, reordered, or changed records and rebuilds the
wire/session/RIB projections rather than trusting a serialized state snapshot.
State, reused-session history query, and NDJSON export are available through the
CLI described in [BGP_STORE.md](BGP_STORE.md).

Imported MRT records now have a sealed exact-source store and share the
replay/state/query/export command surface plus normalized observation admission.
TABLE_DUMP_V2 entries remain directionless collector candidates; BGP4MP message
session replay, BMP, policy CLI, cross-source association, real-corpus evidence,
sustained fuzz, scale, and independent router qualification remain later gates
in the BGP completion contract.

The decoder, observer, RIB, and immutable-input journal each enforce
conservative logical retention/work limits. This composite does not yet provide
a single canonical persisted-size, allocator, CPU, or RSS budget; those
measurements belong to the multi-session product and qualification phases.

Direct tests are in `product/tests/bgp_pipeline.rs` and cover bilateral OPEN to
active route state, multi-NLRI atomicity, conventional and multiprotocol EOR,
NOTIFICATION and malformed-UPDATE reset, gap/reset separation, capture/scope
failure atomicity, and permanent record-identity quarantine. Manager isolation
and lifecycle tests are in `product/tests/bgp_manager.rs`; the real CLI event
path is exercised by `product/tests/pcap_depth_cli.rs`, including bilateral OPEN,
a four-octet-AS UPDATE split across out-of-order TCP segments, clean checksums,
active candidate state, and cross-direction event ordering.
