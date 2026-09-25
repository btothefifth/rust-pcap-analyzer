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
is `pcap-evidence.bgp.mrt-replay.v3`. Each collector candidate is a compact route
summary with `observation_index` and `route_index` references into the retained
candidate-state observation journal; normalized envelopes and route attributes
are not copied into each candidate. Candidate-query v3 includes each referenced
normalized envelope once in its `observations` array, separate `bgp4mp_candidates`
and source-ordered `bgp4mp_events` arrays, so event-only sessions remain
queryable even without an admitted route. Export schema v3 writes a receipt
header, every MRT record summary, source-ordered BGP4MP session events, each
normalized observation once with its journal index, then RIB and BGP4MP
candidate rows that refer to those observations and routes.

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
the BGP4MP AS4 subtype describes the width of the outer MRT peer/local ASN
fields; the UPDATE's AS_PATH width comes from the shared bilateral OPEN
capability context. For 2-byte MRT subtypes, OPEN identity comparison uses the
legacy 2-byte ASN field (including AS_TRANS), not the four-byte capability
value.

The decoding boundaries follow [RFC 6396](https://www.rfc-editor.org/rfc/rfc6396)
and [RFC 8050](https://www.rfc-editor.org/rfc/rfc8050); reported state edges are
checked against the base FSM in [RFC 4271, Section 8](https://www.rfc-editor.org/rfc/rfc4271#section-8).

The exported `bgp4mp_events` preserve source record index, full-record and
message ranges, message digest, endpoint labels, timestamp, state/generation,
parse status, issues, and explicit `source_authenticated: false` and
`endpoint_state_claimed: false` markers. Positive UPDATEs also create compact
`bgp4mp_candidates` bound to the normalized observation, route, exact source
range, partition, direction, and message identity. Candidate resolution checks
those bindings before query deduplication. This is candidate analysis, not proof
of an installed route or endpoint state.

The message-range helper validates structural and byte consistency. Persisted
replay additionally verifies/reparses the original sealed source before it
uses a range. The source parser currently rejects a malformed BGP frame before
an archive exists; semantically invalid but structurally framed messages can be
retained as rejected events. BMP ingestion, captured-versus-imported semantic
equivalence, persisted policy/cross-source
association, multi-checkpoint chronology, crash-resume indexing, broad
real-corpus/scale evidence, and sustained fuzzing remain completion gates.
Full protocol-FSM reproduction—including TCP connection identity/collisions,
timer events, and deciding whether missing state-change records may be inferred
from messages—also remains out of scope for this slice.

`MrtBatch::bgp4mp_message_source_range` locates the exact embedded BGP message
bytes for BGP4MP/BGP4MP_ET message subtypes 1, 4, and 6–11 (including AS4,
locally generated, and ADD-PATH container variants). It checks the embedded
message boundary, subtype-derived layout, address family, and enclosing record
length, then returns absolute source offsets and a digest of the message bytes.
`verified_bgp4mp_message_source_range` additionally binds the batch digest,
original record header/body digest, and message bytes against caller-supplied
source bytes, within a 64 MiB adapter ceiling. These are structural and
byte-consistency checks, not source authenticity or semantic BGP validation;
callers must re-open/reparse the original sealed source before trusting a
persisted range. State-change records and opaque/unsupported payloads do not
produce message ranges. The verified message range is consumed by the
source-ordered imported-session replay described above; the helper itself
establishes byte identity and layout, while shared BGP parsing plus bilateral
OPEN evidence govern semantic use. The supported message subtype map follows
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

MRT report and imported-session query v3 use bounded projections instead of
building an archive-sized JSON tree. The existing NDJSON export remains
row-oriented and lazy over record summaries; each row uses the shared bounded
JSON encoder, while the CLI's byte-budget writer caps the complete output.
Projection file writers measure their line budgets, including trailing
newlines. Session-query output validates candidate references before
deduplicating observations and retains a fallibly grown set of observation
indexes, so its temporary memory still scales with unique observations.
The new BGP4MP event projection borrows retained events during output rather
than cloning them. Schema v3 is intentionally distinct from the previous
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
