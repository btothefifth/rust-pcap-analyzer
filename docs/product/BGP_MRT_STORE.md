# Restartable MRT BGP source store

`deep::bgp_mrt_store` is the persisted external-source boundary for bounded MRT
evidence. It stores the original MRT bytes together with caller-assigned source
and checkpoint labels. It does not persist a derived route projection as truth.
The versioned, dependency-free format uses explicit little-endian container
fields and is portable between supported Windows and Unix targets.

## Import and integrity

Import first parses the entire bounded MRT batch, normalizes every safely
representable TABLE_DUMP_V2 entry, and replays BGP4MP records in source order
before creating the destination. The store contains the exact source bytes,
their SHA-256, and a domain-separated terminal digest over all preceding store
bytes. Fresh readers reject a bad magic/version, truncation, trailing or
changed bytes, invalid labels, inconsistent lengths, source-hash mismatch,
terminal-digest mismatch, and configured resource limits.

The source/checkpoint labels and hashes identify evidence; they do not
authenticate a collector or prove feed completeness.

The CLI opens a regular file, admits one metadata-size snapshot, reserves the
source buffer fallibly, reads exactly that size, and probes one additional byte
to reject truncation or growth before import. The sealed receipt hashes the
exact bytes passed to the MRT parser and store writer; this is byte identity,
not an atomic filesystem snapshot against concurrent same-size overwrites.

The no-overwrite import command requires a new workspace:

    pcap-depth bgp import-mrt dump.mrt --workspace mrt-run \
      --source-id collector-a --checkpoint dump-2026-09-22

It publishes `mrt-run/bgp.mrt` and `mrt-run/receipt.json`. The optional
`--max-mrt-bytes` cap cannot exceed 64 MiB in this version, and
`--max-journal-bytes` bounds the sealed output. Larger sources must be split at
valid MRT record boundaries and imported as distinct checkpoints.

## Fresh replay, state, query, and export

The ordinary persisted BGP commands recognize both captured `bgp.journal` and
imported `bgp.mrt` stores by magic:

    pcap-depth bgp state mrt-run/bgp.mrt --output mrt-state.json
    pcap-depth bgp query mrt-run/bgp.mrt --session mrt:0:0 --output peer.json
    pcap-depth bgp export mrt-run/bgp.mrt --output mrt-evidence.ndjson

Every fresh replay verifies the source store, reparses the MRT grammar,
renormalizes safe RIB entries, replays BGP4MP messages, and admits route
observations through `bgp_state::Observation::from_normalized` and one
transactional `CandidateState::apply_batch` reduction. The replay output schema
is `pcap-evidence.bgp.mrt-replay.v4`. Each collector candidate is a compact route
summary with `observation_index` and `route_index` references into the retained
candidate-state observation journal; normalized envelopes and route attributes
are not copied into each candidate. Candidate-query v4 includes each referenced
normalized envelope and route-free reset/EOR observation once in its `observations` array, separate `bgp4mp_candidates`
and source-ordered `bgp4mp_events` arrays, so event-only sessions remain
queryable even without an admitted route. Export schema v4 writes a receipt
header, every MRT record summary, source-ordered BGP4MP session events, each
normalized observation once with its journal index, then RIB and BGP4MP
candidate rows that refer to those observations and routes, and the native
imported session RIB candidate projection.

The raw source format remains `PCBMRT01`, version 1. Existing sealed stores are
compatible immutable evidence and reopen by verifying and reparsing their exact
source bytes. Their newly derived replay/query/export projection uses v4;
saved v3 projections are historical output and never replay authority. Consumers
that require an exact projection schema must migrate together with v4.

MRT RIB entries bind to the peer-index record immediately preceding their
series. Since parsed records are retained in source-offset order, replay locates
that record with a lower-bound binary search and then verifies the retained
record digest and body type; it does not linearly rescan the record archive for
each RIB entry. The regression `peer_table_resolution_stays_logarithmic_across_many_rib_series`
checks 256 interleaved peer-table/RIB series (512 records) and bounds the
observed lookup probes logarithmically.

The in-memory candidate API resolves these references through
`MrtReplayArchive::candidate_observation`. The index is local to this fresh
replay result, not a stable identifier across source changes or decoder versions.
Resolution checks the observation digest, route fields, source/checkpoint,
record/entry coordinates, session/peer/time, and the retained batch/provenance
binding. Candidate references are validated before query deduplication; a
numeric index or a caller-supplied digest alone is not accepted as identity.

`MrtReplayArchive::batch()` exposes the parsed source as an immutable
reference. Unsupported-entry evidence is cached from that exact batch, so the
archive does not expose a mutable source object that could make the cached
evidence stale after validation. This is an intentional read-only API boundary.

Archive, session-query, and CLI export output streams the typed BGP4MP RIB:
entries, versions, attribute trees, and witnesses are borrowed and measured
before writing. The native RIB line writer also performs an exact full preflight
including its newline. No whole-RIB JSON tree or encoded attribute buffer is
created on those bounded paths. Library `json()` and `bgp4mp_rib_json()` are
convenience materializers; callers choosing them own that additional allocation.
They are outside the bounded streaming writer contract.

Unsupported RIB entries are discovered with a source-order zipper over the
normalized candidate index. The bounded preflight streams rows one at a time
and aggregates exact output growth, retained bytes, and logical work before it
reserves or hashes the final evidence vector. The work charge covers both
preflight/materialization traversals, row sizing/materialization, and hashing
the opaque attribute bytes; it is deterministic accounting, not CPU time or
allocator/RSS accounting. The final SHA-256 has the same fixed-width encoding
as the preflight placeholder, so sizing does not require another archive-wide
serialization pass.

TABLE_DUMP_V2 does not carry a captured endpoint direction or negotiated session
history. Its entries therefore have `direction: null`, remain
`collector_candidate`, and produce `missing_scope` in the shared Adj-RIB-In
candidate reducer. This is intentional: setting a fake direction would turn a
collector snapshot into a false endpoint-state claim. Complete normalized
observations retain source hash, checkpoint, peer-table identity, source ranges,
timestamps, attributes, and import partition.

## BGP4MP source-order replay

BGP4MP and BGP4MP_ET messages share the captured producer's BGP framing, OPEN
capability parser, UPDATE parser, attribute interpretation, and route
normalizer. Imported parsing is source-neutral: it does not manufacture packet
IDs, packet spans, `EvidenceBytes`, or captured-PCAP evidence. Each route
observation carries `import_context` with collector/checkpoint partition,
session, generation, direction, source clock, full-batch identity, and the
exact embedded-message offset range and digest. Its captured `evidence` field
remains null. Collector metadata and hashes still do not authenticate the
source or prove feed completeness.

Each imported route's occurrence carrier also retains exact hex for the message
prefix through the UPDATE attribute-length field and for the message suffix
after the declared attribute block. Together with ordered raw attribute values,
flags, types, and encoded lengths, these endpoints let the generic consumer
reconstruct every TLV and the full BGP message digest. Omitting an unknown
attribute row therefore cannot manufacture complete semantic identity. The
carrier remains message-relative, with no captured packet identity. Aggregate
endpoint/value hex growth and route fanout are preflighted against input,
retained, output, and logical work limits before hex materialization.

Replay follows record order; timestamps, including the exact BGP4MP_ET
microseconds, are preserved but never used to sort records. State-change records
are reported FSM evidence, not endpoint truth. The replay validates reported
transition edges and message-state gates; it does not reconstruct the TCP,
timer, or collision machinery behind the peer's FSM. An UPDATE becomes an imported
route candidate only with a consistent source-order FSM at Established, no
known state conflict, exactly one valid OPEN from each direction, and an
unambiguous shared capability context. Entering Idle retires that generation's
OPEN context; the legal OpenSent -> Active transition also retires the failed
TCP attempt's capability evidence before a retry. Missing or conflicting
evidence is retained as a quarantine event rather than guessed through.

The subtype's ADD-PATH bit selects how that message's NLRI is decoded, but does
not establish bilateral negotiation: parsed path-ID presence is checked against
directional OPEN capability evidence, and a mismatch is quarantined. Likewise,
the BGP4MP message subtype selects both the outer MRT peer/local ASN width and
the embedded UPDATE's AS_PATH wire width: MESSAGE uses two octets and
AS4_MESSAGE uses four octets. Bilateral OPEN evidence independently corroborates
that context; a contradiction is quarantined instead of changing the subtype's
wire grammar. For 2-byte MRT subtypes, OPEN identity comparison uses the
legacy 2-byte ASN field (including AS_TRANS), not the four-byte capability
value.

The decoding boundaries follow [RFC 6396](https://www.rfc-editor.org/rfc/rfc6396)
and [RFC 8050](https://www.rfc-editor.org/rfc/rfc8050); reported state edges are
checked against the base FSM in [RFC 4271, Section 8](https://www.rfc-editor.org/rfc/rfc4271#section-8).

### Imported ROUTE-REFRESH evidence

A 23-byte type-5 message does not by itself establish a supported refresh.
Subtype 0 remains `decoded_route_refresh` in a consistent reported Established
state without requiring Enhanced Route Refresh capability 70. Subtypes 3–255
remain exact source evidence with `ignored_unknown_route_refresh_subtype` and
an explicit issue; they create no route observation, reset, EOR, or RIB change.
This follows the ignore rule in
[RFC 7313, Section 5](https://www.rfc-editor.org/rfc/rfc7313.html#section-5).

For subtype 1 (BoRR) or 2 (EoRR), the imported decoder additionally requires
exactly one valid, unambiguous wire OPEN from the opposite direction in the
current generation, advertising zero-length capability 70. Direction 0 is
peer-to-local, so its receiver advertisement comes from OPEN direction 1;
direction 1 uses OPEN direction 0. A receiver-only advertisement suffices for
this sender-layout condition; a sender-only advertisement does not. The
condition follows the sender procedure in
[RFC 7313, Sections 3.1 and 4](https://www.rfc-editor.org/rfc/rfc7313.html#section-3.1).
The receiver's enhanced error-handling condition in Section 5 is separate and
is not inferred from that sender-layout evidence.

The event detail carries `receiver_open_direction`,
`receiver_capability70_advertised`, and `sender_layout_basis`. A qualifying
advertisement has basis `observed_peer_capability70_for_sender_layout`;
missing, repeated, invalid, and non-advertising receiver OPENs have explicit
distinct bases. `negotiation_established` and `endpoint_processing_claimed`
remain false. Missing capability context yields
`quarantined_route_refresh_capability_context`; an invalid or missing
Established FSM yields `quarantined_route_refresh_fsm_state`. Both dispositions
preserve the source range/digest and mark tracked route continuity uncertain
through the existing quarantine consumer, without inventing a withdrawal.
Wrong fixed message length remains rejected. The decoder does not model ORF,
refresh-driven stale-route cleanup, graceful-restart ordering, or an endpoint's
decision to accept or ignore a marker.

Idle and a failed OpenSent-to-Active attempt clear OPEN advertisements before
the next generation can use them. Fresh store replay reparses the sealed
original stream, so capability evidence is reconstructed from the same
source-order wire messages each time. BMP Peer Up OPENs are reported grammar
context with negotiation unestablished. BMP Route Monitoring accepts only
UPDATE messages; even reported capability 70 cannot qualify an embedded
type-5 message there. The captured producer separately retains an unknown
refresh subtype as unknown with an issue, and does not publish an imported
decoded-refresh disposition.

The finite correction frontier is imported type-5 admission, wire OPEN
advertisement validation, generation reset, sealed fresh replay, the native RIB
quarantine consumer, captured unknown-subtype evidence, and BMP's UPDATE-only
boundary. The regression `bgp_imported_route_refresh` builds its bytes
independently and checks subtype 0, both markers, subtypes 3/255, both unilateral
direction inverses, absent/malformed/repeated receiver OPENs, reset, neighboring
lengths, and reported BMP capability context. Earlier length-only imported
admission had no subtype or capability predicate, so framing positives could
not distinguish a false decoded-refresh label. These fixtures establish
synthetic offline behavior; execution status belongs in the current validation
receipt, and real-source or endpoint protocol qualification remains open.

The exported `bgp4mp_events` preserve source record index, full-record and
message ranges, message digest, endpoint labels, timestamp, state/generation,
parse status, issues, and explicit `source_authenticated: false` and
`endpoint_state_claimed: false` markers. Positive UPDATEs also create compact
`bgp4mp_candidates` bound to the normalized observation, route, exact source
range, partition, direction, and message identity. Candidate resolution checks
those bindings before query deduplication. This is candidate analysis, not proof
of an installed route or endpoint state.

`MrtReplayArchive::bgp4mp_rib` is the typed canonical `AdjRibIn` reducer, not
the legacy read-only projection of generic candidate alternatives. Each
admitted imported UPDATE reduces atomically as one record. Announcements
replace versions, withdrawals change only the exact direction/family/path-ID
key, and reannouncements create new retained versions. Valid route-free EOR
UPDATEs retain their source observation and mark only the declared supported
family, direction, generation, and partition. The `bgp4mp_adj_rib_in` field in
state and session query exposes versions, dispositions, EOR, gap and rejection
evidence. Policy and association consumers must use these native dispositions
when deciding whether an imported candidate is current; generic observations
remain an immutable evidence journal.

Reset events verify source/checkpoint and the exact predecessor, advance only
the matching tracked session partitions by one generation, and supersede old
versions. Historical observations and versions remain. The reset carries no
invented per-prefix withdrawal. A terminal Idle transition affects only its own
peer; failed attempts and tuple reuse cannot borrow sibling OPEN context. No
graceful-restart or LLGR wall-clock timer expiry is inferred.

The message-range helper validates structural and byte consistency. Persisted
replay additionally verifies/reparses the original sealed source before it
uses a range. A complete MRT container with malformed embedded BGP bytes is
retained, sealed and replayed into an explicit rejected event with the exact
record/message ranges and digests. A rejected or context-quarantined message
marks continuity uncertain only in its tracked native RIB session partition;
it does not fabricate reset or withdrawal. Empty embedded messages and malformed
BGP4MP STATE_CHANGE payloads retain exact opaque record bytes, with recovered
scope only when the canonical subtype/address header is complete. Their rejected
events carry the nonempty full-record range and digest, with `message_range: null`.
An identifiable malformed frame clears that session's OPEN/FSM grammar evidence
without advancing its generation. A recognized malformed record whose header
cannot identify its scope yields `quarantined_coverage_unknown`: its session and
peer labels remain null, its coverage is the source/checkpoint, and every actual
tracked scope there receives a gap and loses its decoder grammar evidence.
Ordinary unsupported subtype/AFI opaque evidence is excluded from this malformed
coverage rule. Truncation of the outer MRT
header or declared body remains fail-closed before destination creation.
Neither quarantine nor opaque evidence is a successful normalized route.

An unknown interface or ASN can be compatible with several precise sessions.
`quarantined_ambiguous_session` retains a bounded `detail.affected_scopes` array
of their real session identities and current generations; a synthetic ambiguity
label selects no winner. Every affected tracked native RIB scope receives a gap.
Decoder OPEN/FSM evidence is cleared without changing generation, configured
relationship, or scope. Repeated ambiguity therefore cannot skip the recorded
generation predecessor. Gaps persist within a generation: fresh OPEN/FSM and
same-generation UPDATEs cannot restore active-candidate eligibility. A precise
reported reset retains the checked predecessor, advances only its own scope,
and permits fresh successor evidence to establish candidates in that generation.
Unrelated peers remain unaffected by an identifiable or ambiguous record.
Precise session queries include the complete original ambiguity or unknown-
coverage event when their real ID appears in `affected_scopes`; the event's
synthetic or null top-level session label is preserved. An unrelated session,
or one first observed after the event, does not inherit that raw event. The
borrowed measurement and writer use the same inclusion predicate, including
the exact newline budget and no partial output on a one-byte-short cap.

The five `feedback_` regressions in `bgp_mrt_bgp4mp_replay.rs` exercise all eight
message subtypes with zero/one-byte payloads and both timestamp containers,
malformed state payloads, partial metadata, unknown-interface message/state
ambiguity, repeated ambiguity, precise recovery and reset, and unsupported
neighbors through sealed creation, fresh replay, native RIB state and persisted
active selection, including a new CLI process. Earlier empty-record tests had
no prior route; earlier ambiguity handling cleared decoder evidence without
transporting the affected scopes to the native RIB. The retained F2 baseline
failed four currency oracles and the repeated-ambiguity predecessor oracle.
The post-reset recovery suffix explicitly includes the legal Idle-to-Active
reported transition before its OpenSent sequence; this fixture reachability
correction does not alter the earlier baseline defect location or receipt.
These are bounded synthetic regressions; current execution and source identities
belong in the feedback validation receipt.
Multi-checkpoint chronology, crash-resume indexing, broad
real-corpus/scale evidence, and sustained fuzzing remain completion gates.
Full protocol-FSM reproduction—including TCP connection identity/collisions,
timer events, and deciding whether missing state-change records may be inferred
from messages—also remains out of scope for this slice.

`MrtBatch::bgp4mp_message_source_range` locates the exact embedded BGP message
bytes for BGP4MP/BGP4MP_ET message subtypes 1, 4, and 6–11 (including AS4,
locally generated, and ADD-PATH container variants). It checks the embedded
byte extent, subtype-derived layout, address family, and enclosing record
length, then returns absolute source offsets and a digest of the message bytes.
`verified_bgp4mp_message_source_range` additionally binds the batch digest,
original record header/body digest, and message bytes against caller-supplied
source bytes, within a 64 MiB adapter ceiling. These are structural and
byte-consistency checks, not source authenticity or semantic BGP validation;
callers must re-open/reparse the original sealed source before trusting a
persisted range. State-change records and opaque/unsupported payloads do not
produce message ranges. The verified message range is consumed by the
source-ordered imported-session replay described above; the helper itself
establishes byte identity and layout, while shared BGP parsing and
message-specific OPEN evidence govern semantic use. The supported message
subtype map follows
[RFC 6396](https://www.rfc-editor.org/rfc/rfc6396.html), with ADD-PATH subtypes
defined by [RFC 8050](https://www.rfc-editor.org/rfc/rfc8050.html).

## Deterministic scale checks

The MRT builder preflights aggregate observation work and batches all normalized
RIB observations for one transactional state reduction instead of rebuilding
the whole state after every record. Homogeneous context-free or contextual
batches use indexed identity admission and one derived-state reduction; mixed
legacy/context batches retain the staged sequential validator. The state-level
batch test compares final state and receipts with sequential application and
checks deterministic logical work against the repeated-rebuild path. Source-
sized staging, record, peer, RIB, message and sealed-store byte buffers use
fallible reservation/copy paths before growth. This does not make every nested
allocator operation recoverable or establish a process-RSS ceiling.

MRT report and imported-session query v4 use bounded projections instead of
building an archive-sized JSON tree. The existing NDJSON export remains
row-oriented and lazy over record summaries; each row uses the shared bounded
JSON encoder, while the CLI's byte-budget writer caps the complete output.
Projection file writers measure their line budgets, including trailing
newlines. Session-query output validates candidate references before
deduplicating observations and retains a fallibly grown set of observation
indexes, so its temporary memory still scales with unique observations.
The new BGP4MP event projection borrows retained events during output rather
than cloning them. Schema v4 is intentionally distinct from the previous
projection and the bounded-allocation regression checks escaping, exact limits,
and limit rejection without partial append. These deterministic contract tests
do not establish an RSS, throughput, or real-corpus ceiling.

The
`multi_record_rib_reduction_and_retained_output_growth_are_bounded` test builds
128- and 256-record TABLE_DUMP_V2 inputs independently, checks all candidates
resolve into the single retained observation journal, and requires retained and
serialized output growth to stay below a 3x ratio when records double.

This is a synthetic regression for the former quadratic admission path and
duplicate materialization and peer-table rescan, not a real-corpus throughput,
peak-RSS, sustained fuzz, or production scale qualification. Those remain open.

The native BGP4MP RIB currently applies source events sequentially through the
canonical transactional reducer. Its cumulative logical work and retained
state, versions and projections are charged with the archive against the caller
limits; larger batches may reject rather than evade those limits. The indexed
TABLE_DUMP_V2 reduction does not prove equivalent BGP4MP scale or RSS behavior.
Current authored imported-state selectors cover announce/replace/withdraw,
reannouncement, reset/sibling isolation, supported EOR and unsupported neighbors,
malformed record retention, altered-store rejection, exact output/store limits,
and fresh-process state/query/export. Their executed status belongs in the
current validation receipt. All output remains offline candidates with source
authentication, negotiated endpoint state, installed routes, reachability and
normative qualification unestablished.
