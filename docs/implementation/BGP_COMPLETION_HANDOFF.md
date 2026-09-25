# BGP completion implementation handoff

Status: active implementation handoff. The controlling product contract is
[BGP_COMPLETION.md](../product/BGP_COMPLETION.md); this file translates its
remaining gates into a concrete integration order. Code and tests are the source
of truth when an older narrative differs.

## Mission and stopping condition

Finish the declared offline BGP evidence profile end to end before expanding
other protocol families. Do not stop at field parsing. Completion requires the
normal product path to ingest captured and external BGP, preserve exact source
identity and ambiguity, rebuild state in a fresh process, evaluate configured
policy without invented defaults, query/export/associate evidence, and retain
cross-platform/adversarial qualification receipts.

The implementation may study other analyzers as disagreement probes, but no
external implementation is authoritative. Resolve disagreements from source
bytes, primary protocol specifications, and independently constructed vectors.

Commit and publish meaningful checkpoints to `main`. After every commit, report
the complete capability inventory, validation status, and remaining gaps—not
only the delta in that commit.

## Current accepted architecture

The dependency direction is:

```text
captured TCP bytes / exact external container bytes
        -> bounded framing and source occurrence
        -> source-neutral BGP wire semantics
        -> bilateral session observation and explicit boundaries
        -> normalized route evidence
        -> source-partitioned Adj-RIB-In candidates
        -> optional configured policy candidate
        -> query/export/association
```

Each layer must retain weaker evidence rather than promote it. In particular:

- a collector label/hash is identity, not authentication;
- a TABLE_DUMP_V2 RIB entry has no captured direction and remains a
  `collector_candidate`, not Adj-RIB-In endpoint truth;
- a BGP4MP direction label is adapter evidence, not proof that both endpoints
  negotiated the observed capabilities;
- missing, duplicate, conflicting, reordered, unsupported, or cut evidence is
  explicit and cannot be repaired by a timestamp sort or last-writer choice;
- policy output is an explained offline candidate, not an installed Loc-RIB or
  propagated route;
- association is compatible evidence under declared dimensions and clocks, not
  reachability, causality, attribution, or attack proof;
- persisted projections are never replay authority: fresh replay verifies and
  reprocesses exact source records.

The implementation is dependency-free at runtime, bounded, no-overwrite,
deterministic, and intended to behave equivalently on Windows and Linux. Keep
explicit little-endian custom persistence fields and fail closed on arithmetic,
UTF-8, length, count, work, retention, and output limits.

Large external inputs require asymptotically bounded admission. The current MRT
path reduces homogeneous context-free/contextual observation batches once using
an indexed identity pass, retains compact candidate-to-observation/route
references, and resolves preceding peer tables with a lower-bound search over
source-ordered records. This closes the known repeated full-state rebuild,
candidate-payload duplication, and per-RIB peer-table rescan paths. Mixed
legacy/context batches intentionally retain the transactional sequential
validator. Deterministic synthetic work/growth tests are regression evidence,
not throughput, allocator peak-RSS, real-corpus, sustained-fuzz, or production
scale qualification.

## What is implemented now

### Capture and transport foundation

- classic PCAP and PCAPNG parsing with source hashes, packet offsets, timestamps,
  metadata, and unknown record retention;
- Ethernet/VLAN/SLL/SLL2/raw/loopback, IPv4/IPv6, TCP/UDP, checksums, fragments;
- bounded TCP generations, wraparound, retransmission, out-of-order data, gaps,
  overlap conflicts, coalescing, and split-message provenance;
- `pcap-depth analyze` integrates framed BGP into the normal opt-in depth path.

### BGP wire and session semantics

- BGP-4 framing and OPEN, UPDATE, NOTIFICATION, KEEPALIVE, ROUTE-REFRESH;
- typed capabilities for MP, route refresh/enhanced refresh, four-octet ASN,
  graceful/LLGR, ADD-PATH, extended messages/open parameters, role, and opaque
  unknown capability retention;
- IPv4/IPv6 unicast/multicast NLRI, MP_REACH/MP_UNREACH, ADD-PATH IDs, EOR;
- declared core/common attributes, occurrence identity, duplicate/conflict
  alternatives, RFC 7606-style disposition, AS4 reconstruction;
- bilateral capability context without claiming endpoint negotiation;
- capture-ordered multi-session observation, gaps, resets, tuple reuse,
  NOTIFICATION, stale/EOR/refresh evidence, and immutable-identity quarantine.

### Route state, policy, replay, and association libraries

- source/session/generation/direction/peer/family/path-ID Adj-RIB-In candidates;
- atomic multi-NLRI updates, replacement/withdrawal, EOR, gaps, stale/reset,
  rejected records, retained versions/witnesses, and no silent eviction;
- deterministic best-path candidate evaluation with ordered traces and explicit
  unresolved inputs;
- normalized imported-feed replay with partitions, checkpoints, clocks,
  generation boundaries, quarantine, and coverage receipts;
- generic bounded BGP-to-flow/security association with explicit namespace,
  direction, prefix/endpoint, clock, uncertainty, and coverage policy.

### Persisted capture and MRT product paths

- captured `bgp.journal`: exact reconstructed BGP bytes, every packet span,
  source/capture hash, gap/reset/end/clear records, predecessor hash chain, seal;
- fresh-process captured replay/state/query/export through the real decoder,
  session observer, and RIB reducers;
- external `bgp.mrt`: exact source bytes, source/checkpoint labels, source hash,
  terminal digest, fresh MRT parse, TABLE_DUMP_V2 normalization, shared state
  admission, collector-candidate query/export, and record summaries;
- MRT replay v3 uses compact observation/route references, one transactional
  batch reduction, and indexed peer-table resolution;
- BGP4MP/BGP4MP_ET container records retain endpoints, ASNs, direction labels,
  timestamps, state changes, ADD-PATH declaration, record hash, and exact source
  bytes; opaque/unsupported records remain visible;
- an initial source-ordered BGP4MP event replay now reuses shared OPEN/UPDATE
  parsing and emits capability-gated imported route candidates with exact
  message-range bindings; this slice passes the focused and broader Windows
  local gates recorded below, but is not imported session Adj-RIB-In or a full
  BGP FSM implementation;
- truncation, tamper, trailing data, bad version/magic, source mismatch, output
  overwrite, and one-below output/storage failures are tested.

The public operations are:

```text
pcap-depth analyze CAPTURE --workspace NEW_DIR
pcap-depth bgp import-mrt MRT --workspace NEW_DIR --source-id ID --checkpoint ID
pcap-depth bgp replay|state|export STORE --output NEW_FILE
pcap-depth bgp query STORE --session ID --output NEW_FILE
```

Captured and MRT stores share commands and normalized route semantics but retain
different source/provenance and authority types. Do not collapse their store
formats or assign fake packet spans/directions merely to reuse a captured API.

## Current checkpoint files

The newest slice is centered on:

- `product/src/deep/bgp_mrt_store.rs`
- `product/src/deep/bgp_mrt.rs`
- `product/src/deep/bgp_state.rs`
- `product/src/bin/pcap-depth.rs`
- `product/tests/bgp_state.rs`
- `product/tests/bgp_import.rs`
- `product/tests/pcap_depth_cli.rs`
- `docs/product/BGP_MRT_STORE.md`
- `docs/product/BGP_STATE.md`
- `docs/implementation/CURRENT.md`

The repository's additive product workflow now runs on matching pushes as well
as pull requests/manual dispatch, so product changes on `main` receive Linux and
Windows qualification instead of relying only on root/streaming workflows. The
published MRT persistence checkpoint `58a413e` passed all three native,
streaming, and additive product workflow matrices.

## Remaining implementation order

### 0. Complete MRT admission and bounded-output groundwork (implemented locally)

The current candidate closes the former repeated-rebuild and duplicate
candidate-materialization paths without weakening journal retention or replay
semantics:

- `CandidateState::apply_batch` uses one indexed identity-admission pass and one
  derived-state reduction for homogeneous context-free/contextual batches;
  contextual generations/boundaries remain ordered, and mixed legacy/context
  batches retain the staged sequential validator;
- MRT archive construction preflights aggregate observation work, then batches
  the fresh snapshot transactionally; candidates store observation/route
  indexes, while query/export serialize each referenced normalized envelope
  once under schema v2;
- peer-table resolution is a counted lower-bound search over source-ordered
  MRT records, followed by digest/body verification;
- newly introduced source-sized MRT record, peer/RIB, message, batch, and sealed
  store byte buffers use fallible reservations/copies before growth;
- fixed-snapshot regular-file admission reads only the metadata-sized source and
  probes one byte for concurrent growth; exact BGP4MP/BGP4MP_ET message ranges
  bind layout metadata and original source bytes, while bounded v2 output avoids
  an archive-sized JSON tree and validates candidate identity before dedup;
- synthetic tests prove state/receipt parity, near-linear logical-work growth,
  bounded retained/output growth for 128/256 RIB entries, valid candidate
  references, exact source-range binding, bounded JSON/segmented writes, and
  logarithmic peer lookup across 256 peer-table/RIB series.

Current Windows local validation passes product debug/release all-target,
all-feature suites; product no-default-feature tests; warnings-denied product
Clippy; product docs; root/product/streaming rustfmt; root debug tests and
Clippy; streaming tests; 198 repository Python tool tests (3
platform-conditional skips); and all 61 independent BGP vector tests. The
focused source-ordered BGP4MP replay suite passes 10/10. This is not a
throughput, peak-RSS, arbitrary-OOM, real-corpus, sustained-fuzz, or
production-scale qualification. The historical checkpoint `ed4350e` passed
its recorded native and streaming workflows; those results do not qualify later
source revisions.
These workflow results qualify only the checks they run, not every BGP profile
or the outstanding corpus/fuzz/scale criteria.

### 1. Complete BGP4MP session evidence

The initial source-order, capability-gated candidate-replay slice is
implemented and locally validated. This phase remains the immediate priority
until imported RIB/reset/teardown behavior and cross-source semantic equivalence
are also proved.

1. **Implemented and validated locally:** consume the checked exact absolute source
   range and message digest, verify it against the original sealed source, and
   preserve ET microseconds without using timestamps to reorder records.
2. **Implemented and validated locally:** reuse the source-neutral BGP wire/session
   parser seam from the captured producer. Never construct fake `PacketId`,
   `EvidenceBytes`, or captured `PcapMetadata` for MRT.
3. **Implemented and validated locally:** partition imported sessions by
   source/checkpoint, explicit peer/local addresses and ASNs, interface index,
   and stable session slot. `locally_generated=false/true` maps to a 0/1 adapter
   direction label, not endpoint truth.
4. **Implemented and validated locally:** replay records in source order. Use
   BGP4MP state changes as explicit FSM
   evidence. Entering Idle retires the generation; the legal OpenSent -> Active
   transition reports a failed TCP attempt and also clears that attempt's OPEN
   capability context before retry. A transition into a later Established epoch
   must not inherit old OPEN evidence. Missing state records or missing
   bilateral OPENs leave grammar context unresolved.
5. **Implemented and validated locally:** outer ADD-PATH subtypes may describe
   that record's container layout, but must
   not fabricate bilateral capability negotiation. If outer metadata and OPEN
   evidence disagree, retain both and mark ambiguity/quarantine rather than
   choosing one silently.
6. **Partial:** route BGP4MP OPEN/UPDATE/control records into event evidence
   and capability-gated imported UPDATE candidates. Implement true imported
   session Adj-RIB-In actions, teardown withdrawals, and complete malformed
   source-record retention; the MRT structural parser currently rejects bad
   frames before a replay archive can retain them.
7. **Partial test coverage:** current cases cover source-order chronology,
   bilateral OPEN context, retry reset, illegal transitions, ASN/AS_TRANS and
   container-width conflicts, ADD-PATH quarantine, ET timestamp offsets, exact
   provenance, and black-box import/persist/fresh-replay/query/export. Add the
   remaining independent malformed/truncation/conflict and limit cases as the
   session-state implementation is completed.
8. Still add a positive semantic-equivalence join: equivalent captured and BGP4MP
   UPDATEs must produce matching route meaning while source kind, partition,
   direction authority, and provenance remain observably distinct.

Do not call this phase complete merely because BGP4MP bytes parse or candidate
rows are emitted. Completion requires imported fresh-process route/session
state, teardown semantics, malformed-record retention, and ambiguity-safe
captured-versus-imported semantic equivalence.

### 2. Persisted policy command and richer queries

1. Add `bgp policy STORE --config PROFILE --output NEW_FILE` using a strict,
   versioned, bounded configuration format. Reject duplicate/unknown fields and
   do not add a permissive general-purpose parser only for convenience.
2. Map only evidenced route attributes into `BestPathInputs`. Router-local
   inputs such as local-origin, IGP cost, peer class, MED comparison scope, age
   clock, and defaults require explicit configuration/evidence; absent values
   remain unresolved.
3. Preserve every candidate and complete ordered comparison trace. Selection
   must be deterministic under input permutation and stop at the first decisive
   criterion. Never invent a policy winner to make the CLI look complete.
4. Add prefix/family/peer/source/checkpoint/status filters to query without
   changing source partitions or timestamp-order semantics.
5. Test exact/one-below input, work, retained, and output budgets; no-overwrite;
   equal/final-tiebreak; missing config; multiple source partitions; stale,
   rejected, and conflict alternatives; fresh-process replay invariance.
   Measure output against the versioned canonical serialized bytes, not Rust
   `Debug` formatting or an estimate detached from the persisted representation.

### 3. Persisted multi-source evidence and correlation

1. Add a versioned workspace/manifest that references sealed captured and MRT
   stores by exact digest. Never copy a projection into a new namespace or
   implicitly merge equal route bytes from different sources.
2. Normalize captured and external route events into a queryable common evidence
   view while preserving source kind, partition, checkpoint, generation,
   direction, clock, trust, and coverage.
3. Connect the existing association engine to persisted route and internal
   flow/security evidence. Require explicit join dimensions and clock policy;
   preserve unresolved matches and alternatives.
4. Add positive and negative end-to-end tests for prefix containment, exact
   endpoint, opposite/equal direction, signed timestamps, uncertainty overlap,
   missing clocks, incomplete capture/feed coverage, duplicate evidence, and
   equal semantics from distinct sources.

### 4. BMP external adapter

Implement bounded BMP common/per-peer headers and route-monitoring/statistics/
peer up/down/initiation/termination records only after BGP4MP and persisted
multi-source contracts are stable. Preserve original bytes and peer-header
identity; route embedded BGP through the source-neutral decoder. Unknown message
types and TLVs remain opaque. Do not infer collector authenticity or router RIB.

### 5. Declared-profile closure and qualification

Reconcile every row in the BGP support matrix against code and direct tests.
Then add:

- independent RFC/IANA vectors and intentional mutations;
- sustained fuzz campaigns for wire, MRT/BMP, state, policy, and stores;
- lawful real capture and route-collector corpora with source hashes/licenses;
- disagreement/minimization probes against other analyzers, adjudicated from
  bytes/specifications rather than majority vote;
- scale, memory/RSS, throughput, large-route-count, restart/corrupt-checkpoint,
  and multi-checkpoint chronology receipts;
- Windows/Linux CI for every claimed gate, with macOS compatibility retained
  where the existing workflows support it.

Only then change qualification wording from source candidate/partial. Keep
unsupported profiles explicit, especially BGPsec validation, active peering,
encrypted data, vendor-private semantics, and unimplemented AFI/SAFI families.

## Required validation at each checkpoint

Run the smallest focused tests during edits, then before publication run:

```text
cargo fmt --manifest-path product/Cargo.toml --all -- --check
cargo test --manifest-path product/Cargo.toml --locked --offline --all-targets
cargo test --manifest-path product/Cargo.toml --locked --offline --release --all-targets
cargo clippy --manifest-path product/Cargo.toml --locked --offline --all-targets --all-features -- -D warnings
cargo test --manifest-path product/Cargo.toml --locked --offline --no-default-features --all-targets
cargo doc --manifest-path product/Cargo.toml --locked --offline --no-deps --all-features
cargo test --locked --offline --all-targets
cargo clippy --locked --offline --all-targets -- -D warnings
cargo test --manifest-path streaming/Cargo.toml --locked --offline --all-targets
python -m unittest discover -s tools/tests -v
```

Also run `git diff --check`, repository rustfmt checks, the independent BGP
vector scripts named by the support matrix, a forbidden-name/private-path scan,
and the exact GitHub Actions workflows affected by the commit. A green test is
not sufficient if documentation claims more authority or qualification than the
test proves.

## Review traps to avoid

- Do not deserialize a saved state projection as replay authority.
- Do not make MRT TABLE_DUMP entries active by assigning direction zero.
- Do not use BGP4MP timestamps to repair or reorder source chronology.
- Do not treat a BGP4MP ADD-PATH subtype as bilateral OPEN negotiation.
- Do not reuse the captured packet API by fabricating packet provenance.
- Do not default missing router policy inputs merely to force a winner.
- Do not merge sources because message bytes, route keys, or hashes match.
- Do not weaken tests, drop unsupported records, or silently evict state to stay
  within a budget.
- Do not call other analyzers authoritative; use them to find disagreements.
- Do not call synthetic local tests real-corpus, scale, fuzz, security, live, or
  normative qualification.

## First action after takeover

Verify `main`, upstream identity, clean status, the current GitHub workflows, and
the latest product validation receipt. Read this handoff, the controlling BGP
contract, `CURRENT.md`, `bgp_mrt.rs`, `bgp/mrt.rs`, `bgp_mrt_store.rs`,
`bgp_pipeline.rs`, and the producer/session/RIB tests. The MRT
reducer/archive-reference and peer-table
lookup improvements now also have bounded source-read/output and exact BGP4MP
source-range validation. The source-ordered, capability-gated candidate-replay
slice passes native Windows debug/release/no-default tests, focused CLI/replay
tests, warnings-denied Clippy, independent BGP vectors, and repository tool
tests. The next action is to implement imported session Adj-RIB-In/reset/
teardown semantics and prove captured-versus-BGP4MP semantic equivalence before
moving to policy or BMP.
