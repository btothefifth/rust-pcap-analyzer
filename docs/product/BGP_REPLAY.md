# Bounded normalized BGP feed replay

## Replay serialization accounting and transactional publication

The replay-owned encoder now measures exact compact JSON length without first
rendering a document. The checked traversal counts punctuation, decimal `u64`
widths, UTF-8 bytes and JSON escapes, preserving the shared encoder's byte format.
Depth, node, string, duplicate-key, authority and provenance-reference checks
still run before canonicalization. A number's sizing loop reserves 20 logical
work units before inspecting its decimal width. Checked addition/multiplication
rejects overflow; no limit is increased or silently bypassed.

Before canonical cloning or rendering, the encoder reserves **four work units
per exact serialized byte**, retaining the prior serialization-cost model.
The existing shared `Json::encode_bounded` remains the sole JSON writer and
independently verifies the measured output size; it renders once. There is no
serialize-to-measure pass, and the canonical receipt tree is reused rather than
cloned a second time. Pure size/admission checks likewise use counting, not
throwaway JSON strings. These logical units are not a CPU-instruction, allocator,
RSS or hard-time guarantee. This repair does not introduce another JSON writer or
change the shared root JSON API.

Replay-owned work is carried through record/page checks, retained-record
preflight and staged receipt refresh instead of replenishing the encoder's
counter. Structural counts continue to describe the corresponding input or
retained-evidence view, rather than counting every validation pass as newly
retained evidence. Association-receipt counting and encoding share their replay
handoff guard, while aggregate route/note node and reference checks remain intact.
The imported validator, candidate reducer and association builder retain their
own existing limits and admission contracts; their internals and existing replay
adapter-work estimates are not redefined as exact instruction counts here.

A byte limit is inclusive: output of exactly that size succeeds when the other
budgets suffice; one byte below fails. Work reservation is also inclusive.
Some operations previously accepted by separate per-phase work counters may now
fail their combined replay-owned budget. This is an intentional fail-closed
accounting correction, not a schema or successful-output change. Do not increase
limits automatically, retry with a weaker policy, or treat a rejected envelope
as validated evidence.

`FeedReplay::apply` still works on a staged clone and replaces the caller's
instance only after receipt validation, size/work checks and outcome construction.
On any rejection, candidate journal, ordered records/alternatives, generation,
completion, quarantine, cursor commitments and receipt bytes stay unchanged.
Association handoffs remain read-only and are returned only after their complete
encoding passes. Exact replay is still a no-op; a work rejection cannot publish a
new replay receipt or reapply old effects. Finalization and conflict quarantine
retain their existing meanings and coverage restrictions. No timestamp, source
identity, batch/checkpoint, authority label, path or generation policy changes.

### Focused evidence for this accounting repair

`product/src/deep/bgp_replay/accounting_tests.rs` adds 16 native tests. They cover
fixed scalar work thresholds, cumulative reservations, every ASCII control escape,
UTF-8, integer widths, nested canonical output, exact output caps, one-below caps,
record application and replay, finalization, conflict quarantine, generation
failure after a valid first record, and read-only association receipts. Every
rejected mutation trial checks state/journal/cursor/receipt bytes, including the
historical candidate state in a quarantined instance. The tests retain the
existing independently specified feed/prefix commitment vectors.

`python3 -B product/tests/bgp_replay_accounting_vectors.py -v` adds seven independent
standard-library arithmetic/encoding vectors. The existing nine replay-vector
tests are unchanged. Both Python suites passed in the authoring environment;
neither executes Rust. The 16 new Rust tests and existing native suites were
**not run** because `cargo`, `rustc`, `rustfmt` and Clippy are unavailable here.
Earlier integration receipts remain historical, not native proof for this change.
Run in a complete checkout:

```sh
cargo test --manifest-path product/Cargo.toml --locked --offline --lib deep::bgp_replay::accounting_tests
cargo test --manifest-path product/Cargo.toml --locked --offline --test bgp_replay
cargo test --manifest-path product/Cargo.toml --locked --offline --test bgp_import --test bgp_state --test bgp_association --test bgp_producer
cargo fmt --manifest-path product/Cargo.toml --all -- --check
cargo check --manifest-path product/Cargo.toml --locked --offline --all-targets
cargo test --manifest-path product/Cargo.toml --locked --offline --all-targets
cargo test --manifest-path product/Cargo.toml --locked --offline --release --all-targets
cargo clippy --manifest-path product/Cargo.toml --locked --offline --all-targets --all-features -- -D warnings
```

Keep the existing root/streaming and product feature/release matrices. Complete-
checkout application, native execution, external source verification, automatic
sink forwarding, source-specific adapters, full capability/AS4 replacement
semantics, live/scale/fuzz/security and normative qualification are not established
by this repair. The producer contract's earlier replay-accounting follow-up is
addressed only at this replay-owned boundary; all its unrelated deferred findings
remain open. The return-package review lists inspected surfaces and dispositions.

### Local integrator validation

The worker-side limitation above is not the final repository validation. On
2026-09-21, a complete isolated Windows checkout at the pinned base passed the
16 focused replay-accounting unit tests, all product debug all-target tests,
product `cargo check`, product Clippy with `-D warnings`, all product release
all-target tests, the focused BGP Python vectors, the portable product validator,
and the repository `scripts/validate.py` receipt. The root crate's configured
format/build/test/Clippy checks also passed. A repository-wide product
`cargo fmt --check` still reports pre-existing formatting differences in
untouched product files; the new accounting test module itself is rustfmt-clean.
No external source, live traffic, fuzz, scale, or normative qualification claim
is implied by these local gates.

## Captured BGP producer parity — source candidate

The captured producer extension in [BGP_PRODUCER.md](BGP_PRODUCER.md) stages
`decode_pcap` state until complete budget and output checks succeed. It binds
source/session/capture context, retains both OPEN directions and repeated
advertisements, exposes exact capability and path-attribute occurrences, and
uses the first ordinary path-attribute occurrence as the only semantic candidate
(subject to its own validation) while retaining later occurrences with explicit
discard dispositions. Repeated
MP_REACH_NLRI or MP_UNREACH_NLRI requires session reset. Repeated OPENs
no longer infer a new generation. A missing session produces unknown generation,
not another session's state. Negotiation and all authority claims remain false.

Imported normalizer bytes and import/state/replay partition, clock, checkpoint
and boundary contracts remain unchanged. The new occurrence value coordinates
are validated by state admission and excluded from state/association path
identity, while their evidence is retained. Captured output gains additive fields;
strict consumers and event hashes must account for the documented migration.

This worker has not executed Rust. New native tests are authored, not passing
receipts. Earlier Windows evidence is historical; complete-checkout application,
native workspace matrices, cross-platform/runtime, live, scale, fuzz, secure and
normative qualification remain open. External source verification and adapters
are outside this producer. Review findings and exact remaining boundaries are
recorded in the producer contract and returned handoff.

`pcap_evidence_product::deep::bgp_replay` is an opt-in, I/O-free replay seam over
caller-adapted normalized imported BGP evidence. It reuses `bgp_import::ImportContext`,
`bgp_state::Observation`, `CandidateState`, and association `Coverage`. It does not
introduce another attribute parser, clock model, source adapter, or route selector.

**Source candidate; native acceptance is not established by this worker.** The
new Python vectors check independent identity arithmetic, not Rust behavior. The
new native tests and the complete-checkout gates in `VALIDATION.md` must be run
before accepting this addition. Earlier local Windows acceptance describes the
published import/state/association baseline, not this replay extension.

## Versions, ownership and declared scope

The typed page envelope is `pcap-evidence.bgp.replay-feed.v1`; replay receipts use
`pcap-evidence.bgp.replay-receipt.v1`; the association handoff receipt uses
`pcap-evidence.bgp.replay-association.v1`. The `.v1` schema identifier declares
this envelope version. Upstream source schema/version are not invented or copied
into a competing model: they remain in the existing `ImportContext`.

A replay instance owns exactly one immutable source/session/import partition.
Its declaration is the existing `ImportContext`, with `direction=None` and its
`generation` interpreted as the initial declared generation. Source ID, source
schema/optional version, immutable batch ID/hash/optional byte length, checkpoint,
session, peer/local, clock policy/ID/uncertainty and declaration provenance must
stay identical across pages. Per-record contexts retain their own generation,
direction and ordered source ranges. Record partition and full clock declaration
must match the feed. The full clock is fixed in this bounded slice; varying a
clock or its uncertainty within a feed is rejected, not normalized away.

Another checkpoint, batch, hash, schema/version, session or declaration requires
an independent instance starting at ordinal zero. It is not a continuation or an
implicit withdrawal of another instance. Cross-checkpoint transfer, arbitrary
mid-sequence bootstrap, merging instances and persistence/loading are not
implemented. A caller can replay a retained prefix to rebuild an instance; a
plausible cursor alone cannot authorize omitted history. A partial feed starts
at its declared beginning, not at an unknown external offset.

Only normalized **contextual imported** records enter this seam. Legacy imports
with unknown batch/generation and captured records are not relabeled; they remain
usable through their existing APIs. Captured and contextual imported observations
still share the existing `pcap-evidence.bgp.route-evidence.v1` shape. Captured wire
verification, external-source verification, source adaptation, privacy/redaction,
and operational ingestion all remain caller responsibilities.

## Typed API

- `FeedRecord::from_normalized(ordinal, &Json, Coverage, &Limits)` validates and
  freezes the existing normalized envelope. It requires an immutable record ID,
  full import context, and either routes or a normalized generation boundary.
  Source identity, clocks, uncertainty, path attributes, prefix/action, unknown
  extensions, issues and provenance are retained. `observation()`, `coverage()`,
  `ordinal()` and `encode()` are read-only.
- `FeedEnvelope::new(ImportContext, Cursor, Vec<FeedRecord>, Completion, &Limits)`
  validates one contiguous page in supplied order. It does not sort timestamps
  or manufacture record identifiers, ordinals or a predecessor. Its canonical
  encoding is a publication representation, not a source-specific input format.
  Callers construct typed pages; there is no new arbitrary JSON/text parser.
- `FeedReplay::new(ImportContext, Limits)` creates an empty partial sequence and
  its initial cursor. `apply(&FeedEnvelope)` returns `ReplayOutcome` only after
  staged reduction, complete output sizing and all checks succeed. `records()`,
  `receipt()`, `cursor()`, `completion()` and `is_quarantined()` expose the state.
- `candidate_state()` returns an immutable view when the feed is not quarantined.
  That view retains the existing candidate-state semantics; it is not an RIB.
  After a changed ordered record, it returns a typed error rather than expose the
  original candidate as a selected winner. Evidence remains in the replay receipt.
- `association_receipt(&RouteContext, &Limits)` returns an immutable
  `AssociationReceipt` containing the existing `RouteBatch` and a receipt binding
  it to the replay context, full ordered witnesses, coverage and snapshot hash.
  Pass `routes()` to the existing `bgp_association::associate` with an explicit
  policy, and retain `encode()` alongside that result.

There is no implicit association namespace, flow mapping, comparable clock,
causal timing, new CLI flag, event projection, transaction or external ingestion.
The only change to an existing runtime type is `Clone` on `CandidateState` for
bounded staging. Its fields remain private; existing reduction behavior and
producer, import, association, streaming and DNP3 contracts are unchanged.

## Order, checkpoints, replay and conflict

Record ordinals are zero-based and contiguous. Record identity is the immutable
source/session/partition and record ID **at its declared ordinal**. A page may
start at any prefix already retained by the same instance and replay an exact
overlap before adding a contiguous suffix. Cursor fields must match that retained
prefix, including the feed-declaration digest. Missing, changed, skipped or
cross-partition cursors fail. Reversed/skipped ordinals fail before application.
Moving an existing record ID to another ordinal is an explicit reordered-identity
error, not a second observation with an inferred timestamp order.

Exact replay compares complete canonical record content, not a hash alone.
It returns `IdenticalReplay` and does not change the journal, counters, cursor,
receipt bytes or candidate-state bytes. This includes replay after an accepted
boundary or final marker. A previously unaccepted explicit `Final` marker is a
`Finalized` operation, not identical-envelope replay, even without new records;
it changes the replay receipt while leaving the candidate journal unchanged. JSON object-key order is canonicalized; record arrays,
source ranges, attributes and historical alternatives preserve their input order.
For one non-conflicting sequence, page segmentation and exact overlapping replay
do not change final receipt or state bytes. This is not order-independent state
reduction and does not sort observations by time.

Changed valid content, coverage or record ID at an existing ordinal is retained
as a full alternative with `Quarantined`. The whole replay partition becomes
unavailable for candidate/association access. The original journal index is only
a historical reference, not a winner. All alternatives remain visible; identical
replay of an alternative is also a no-op. A changed historical record is handled
before current-generation reduction, so it cannot revive an old route through a
reset. Quarantine cannot be cleared by repetition, a new boundary or a final marker.

A page containing both a conflicting overlap and an extension is rejected
atomically: the conflict cannot authorize the new suffix. Malformed/conflicting
boundary transitions and exhausted retention budgets also return errors without
partial publication. The rejected envelope remains caller-owned. Callers must
retain and report errors rather than continue using an old receipt as proof that
the rejected evidence was clean.

Different immutable records with differing path attributes still enter the
existing reducer as alternatives. Those are path conflicts, not ordered-record
identity conflicts. Neither imported origin, repetition, timestamp nor a numerical
path preference selects a winner. Unsupported prefixes remain retained and have
no active route effect; unknown fields are not silently discarded.

## Explicit generation boundaries and completion

All initial route records must match the declaration's initial generation.
Subsequent new records must match the current generation. A boundary is produced
by the existing `bgp_import::normalize_boundary`: it names the current predecessor
and its checked exact successor, with no direction and a reason. The existing
reducer must also find that unambiguous predecessor in the same partition. No
missing, reversed, skipped or overflowing generation transition is guessed.
An unknown-direction observation does not create a predecessor that authorizes a
boundary. An accepted reset retires both directions under the existing rules.
Old exact replay never reapplies a retired announcement or withdrawal.

`Completion::Partial` says only that the declared sequence is not final.
`Completion::Final` seals exactly the accepted extent; a final marker cannot omit
an already retained tail. Empty partial/final pages are supported. Once final,
no new suffix is allowed, although exact replay and conflict evidence for existing
ordinals remain possible. A conflict never converts a partial feed to final.
Final means end of this declared sequence, not complete capture, all routes,
source verification, successful ingestion or endpoint state.

## Cursor and receipt identity

Let `H` be SHA-256 and `D` the byte string
`pcap-evidence/bgp/replay-prefix/v1` followed by one NUL byte. With canonical
compact JSON `J`:

- feed digest: `H(J({schema: FEED_SCHEMA, context: declaration}))`;
- prefix zero: `H(D || ASCII(lowercase_hex(feed_digest)))`;
- next prefix: `H(D || ASCII(lowercase_hex(previous_prefix)) || J(record_wrapper))`.

The wrapper contains decimal-string ordinal, coverage label and full normalized
observation. `Cursor` carries feed digest, next ordinal and prefix digest.
Published fixtures give independent expected values. Prefix commitments identify
the initially accepted sequence; they never adjudicate later conflicts. After
quarantine they cannot authorize extension, and the candidate-state digest in
receipts becomes null. The current generation is also null rather than selecting
one historical generation as current. Every original/alternative generation stays
in its normalized evidence. The complete receipt digest includes the alternatives.
Hashes identify bytes and detect substitution; they do not authenticate a source.

Every receipt preserves the declaration, current generation, next cursor,
completion, effective coverage and ordered original/alternative normalized records.
`state_observation` is a historical index into the owned reducer journal. Relevant
source/batch/checkpoint/generation/clock/provenance dimensions remain inside those
unchanged normalized records. Endpoint, RIB, best-path, reachability, attack,
causality, source-authority, source-verification and normative claims are false.

## Association coverage and receipts

The adapter conservatively meets caller-supplied coverage with feed coverage:
partial or quarantined sequences are incomplete; for final sequences any
incomplete record wins over unknown, and unknown wins over declared complete.
A final empty sequence has no route witnesses; vacuous declared-sequence coverage
does not make an association candidate. `Final` never upgrades an unknown record.
The effective coverage applies to the whole borrowed snapshot in this bounded
adapter. Per-record precision is retained in the receipt; a finer-grained
association coverage adapter is separate future work.

The existing association adapter retains inactive routes and boundary notes.
Their source evidence also consumes this adapter's retention/reference budgets.
Clock overrides are rejected, including for an empty feed. Quarantined feeds
return an error with the full replay receipt still available separately. For
non-quarantined feeds, namespace/flow context and comparison policy remain
explicit caller assertions, never equivalence inferred from similar labels.
Time labels remain signed labels, absent time remains null, and uncertainty
remains exactly as supplied. There is no time ordering, expiry or causal claim.

## Bounds and atomicity

All constructors and consumers take existing `deep::Limits`. The feed declaration
uses the existing import identity/hash/range bounds. Records/pages are validated
again under the replay instance's limits, even if constructed with larger ones.

| Limit | Replay meaning |
|---|---|
| `input_bytes` | Each normalized record, typed page and declaration; aggregate page encoding; association input receipt |
| `fields`, `depth` | Node and nesting bounds before canonical cloning; aggregate retained record validation and complete receipt tree |
| `elements` | Per-page and retained original/alternative records, ordinal extent and aggregate route records |
| `spans` | Aggregate declaration/record source references, including alternatives, and association route/boundary witnesses |
| `active` | Existing reducer partition/session bounds; one feed partition per replay instance |
| `retained_bytes` | Canonical record journal, cursor accounting, reducer logical storage and completed replay/association receipt |
| `work` | Logical validation, comparison, staged reduction and serialization passes before publication |
| `output_bytes` | Exact canonical page/record/receipt output sizes and existing state/association output bounds |

Preflight checks retained counts, nodes, references, bytes and work before
staging. The existing reducer applies only to a clone. Final serialization and
all remaining accounting finish before the clone is committed. An error leaves
the prior replay, state, cursor and receipt unchanged. No partial callback,
silent eviction, scope downgrade, guessed boundary or retry with weaker limits
is supplied. The caller must record the rejection rather than imply completeness.

Logical budgets are not allocator/RSS or CPU-time guarantees. Original inputs,
bounded staged clones, source views and encoded snapshots can coexist; callers
own aggregate budgets across independently constructed instances. `Clone` is not
an OS memory sandbox. Storage/load, arbitrary cursor resume and source-byte
verification are outside this implementation.

## Review and validation boundary

The published import/state/association code and contracts were reviewed, including
association coverage, inactive witnesses, immutable partitions, generation checks,
JSON guards and native test sources. The review was not clean: no feed sequence/
completion contract existed; a blanket caller coverage value could not express
feed completeness; changed historical record conflicts required handling before
current-generation checks. This wrapper fills those gaps, preserves stricter
identity/authority guards at its boundary, and keeps quarantine receipts available
without exposing the old candidate view. No accepted tests or rules are weakened.

At this replay-integration checkpoint, deferred issues included direct captured-
producer budget parity, decoder-state staging before later failures, arbitrary
captured direction validation, full capability/session adjudication, duplicate
scalar attribute semantics, actual source verification and reliable production
boundary forwarding. Later producer work closes the direct budget/staging and
ordinary/repeated-MP duplicate-disposition items. Direction validation, complete
capability/session adjudication, source verification and reliable production
boundary forwarding remain open; this replay wrapper does not supply them.
See the job's `SUMMARY.md` and `REMAINING.md` for the exact review dispositions.

The focused native suite is `product/tests/bgp_replay.rs`. Independent Python
vectors in `product/tests/bgp_replay_vectors.py` check declaration/prefix hashes,
record order, altered content and explicit-successor arithmetic. Neither vector
agreement, patch application nor packaging integrity proves native execution.
Run the focused tests, unchanged BGP suites, root/product/streaming gates and
feature matrices before acceptance. Windows, Linux/macOS runtime, live, scale,
fuzz, external-corpus, security and normative gates require their own evidence.
