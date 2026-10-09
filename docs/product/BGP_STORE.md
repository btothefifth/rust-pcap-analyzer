# Restartable captured BGP source journal

`deep::bgp_store` is the Phase 5 persistence boundary for captured BGP evidence.
It persists source records, not trusted derived state. The format has no runtime
dependencies and uses explicit little-endian fields so the same bytes are
readable on Windows and Linux.

## Integrity and publication

The versioned header binds the complete-capture SHA-256 namespace and source
label. Every record contains the previous digest and a SHA-256 over its type,
length, predecessor, and body. Message records contain exact reconstructed BGP
bytes, direction/session metadata, and every packet source span. Gap, explicit
reset, flow-end, and whole-capture boundary records preserve lifecycle.

Only a terminal seal with the exact preceding-record count is accepted. Readers
reject unknown kinds/versions, changed digests, broken predecessor links,
truncation, trailing bytes, foreign capture spans, invalid UTF-8, invalid
directions, and configured disk/input/span/session/output limit violations.
`pcap-depth analyze` writes `bgp.journal.partial` and promotes it to
`bgp.journal` only after source analysis and journal sealing succeed.

The digest chain is tamper evidence and source identity, not a signature,
authentication statement, or proof that the capture is complete.

## Replay and query

`bgp_store::replay` creates a new `CapturedSessionManager` and feeds every exact
source record through the normal wire decoder, session observer, and Adj-RIB-In
candidate reducer. It never loads a serialized state projection as authority.
Rejected message/boundary records remain counted; successful and ended session
snapshots retain routes, versions, witnesses, status, gaps, resets, bilateral
capability context, and source partitions.

A known-session BGP framing failure records a source-bound continuity gap because
the framer did not admit a MESSAGE for those bytes. An admitted BGP scope journals
and applies the gap immediately. Before the first managed BGP MESSAGE, the gap
remains pending until that MESSAGE admits the scope. An issue-only lifecycle
that ends without an admitted MESSAGE retains capture evidence without creating
a BGP journal scope. The original issue's bytes
and packet spans remain available in the capture event, linked by its immutable
event ID and the journal's complete-capture namespace. A deep non-budget
rejection instead retains its exact MESSAGE record; replay derives its scoped
gap from that record. The capture sink applies the same continuity consequence
immediately without writing a duplicate GAP. Gaps preserve route history and
make existing and later same-generation candidates unresolved; they do not
invent withdrawals or resets. The ordinary analyze path stops on budget or
boundary-admission errors before sealing and publishing its journal. Replay
also stops on resource-limit errors. A caller must stop after an EventSink
error rather than ignore it and request publication.

Native rejected announcement actions remain separate typed occurrences in the
replay archive. Each is bound when the reducer emits it to the exact normalized
observation and its verified journal record/lifecycle witness. END and CLEAR
retain those occurrences before dropping the session; a reused session label
cannot rebind them. Rejection retention and clone admission are charged before
copying under the caller's element, retained-byte and work limits. These actions
neither overwrite an accepted candidate nor imply a continuity gap or withdrawal.

Flow-end snapshots retain terminal history. Persisted rich route rows from an
ended lifecycle expose `native_current=false`, even when their last observed
route status is Active, and remain excluded from current policy selection.

The no-overwrite commands are:

    pcap-depth bgp replay RUN/bgp.journal --output replay.json
    pcap-depth bgp state RUN/bgp.journal --output state.json
    pcap-depth bgp query RUN/bgp.journal --session N --output session.json
    pcap-depth bgp export RUN/bgp.journal --output sessions.ndjson

`replay` and `state` currently produce the same complete replay document.
`query` returns all occurrences of a reused analysis-session ID. `export` writes
one journal header followed by one line per lifecycle snapshot. Output is an
offline evidence candidate and never claims endpoint RIB installation,
negotiation, reachability, causality, or source authenticity.

`--max-journal-bytes` bounds accepted input and `--max-output-bytes` bounds new
output. The analyze path separately accepts `--max-bgp-journal-bytes`. A budget
failure leaves a `.partial` recovery artifact and never publishes the requested
final path.

## Current boundary

This journal owns captured BGP records from `pcap-depth`. MRT now has a separate
source-first store because its container identity and direction semantics differ;
both formats share the replay/state/query/export command surface and normalized
route-evidence admission. See [BGP_MRT_STORE.md](BGP_MRT_STORE.md). Imported
BGP4MP message-session replay, BMP ingestion, policy/query selection,
cross-source association, crash-resume checkpoints, long-duration fuzzing, real
corpora, and scale/RSS receipts remain explicit completion gates.
