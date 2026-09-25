# Bounded imported BGP evidence context

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

## Typed feed replay consumer

[BGP_REPLAY.md](BGP_REPLAY.md) defines an opt-in ordered envelope around this
existing context. It does not duplicate batch, schema/version, clock, provenance
or generation types. A feed declaration uses `ImportContext` with no direction
and an initial generation; per-record generation/direction/ranges stay in the
normalized record. Its full clock declaration is fixed for the feed. Changed
checkpoint/batch/declaration requires a fresh isolated sequence, not continuation.

Legacy imports remain readable by existing consumers but cannot enter replay
without full contextual identity. No adapter or source verification is added.
Exact replay does not reapply old effects; changed ordered records are retained
and quarantine candidate access. Native replay acceptance remains unrun here.

## Optional candidate association consumer

The distinct API in [BGP_ASSOCIATION.md](BGP_ASSOCIATION.md) consumes these
normalized records without changing their source kind, batch/hash/checkpoint,
source schema/version, session/generation, clock labels or provenance. Contextual
import clocks cannot be overridden at association time. Legacy records with no
immutable context remain explicitly unresolved rather than receiving a fabricated
batch or checkpoint. Different partitions remain different route witnesses.

The association namespace and comparison policy are explicit caller assertions,
not a source-specific adapter or an automatic cross-source join. Neither imported
nor captured evidence is preferred. Time labels and reported uncertainty never
establish packet order, clock accuracy, reachability, attack or causality.
The worker's unrun checks are documented separately in VALIDATION.md; the
integrator subsequently ran the complete association and product/workspace
native gates in the local Windows checkout.

Source candidate based on `1de3c4f4b30a67eea8ee752144b39867995bb51a`.
The worker host lacked Cargo/rustc/rustfmt/Clippy, but this exact reviewed tree
has since passed the local Windows native product/workspace gates listed in
`VALIDATION.md`. No live, cross-platform runtime, scale, fuzz, secure or
normative claim is made.

## Ownership and API

`pcap_evidence_product::deep::bgp_import` is an opt-in normalization seam, not a
feed adapter. It performs no I/O, network lookup, credential handling, packet
reconstruction, external-source preference, flow join or route selection.
The normalized envelope remains `pcap-evidence.bgp.route-evidence.v1`.

- `ImportContext` carries a required source ID, source-schema identity, optional
  version, `ObservationClock`, immutable `SourceBatch`, checkpoint ID, session,
  explicitly supplied generation, optional direction/peer/local and ordered
  `SourceRange` provenance. `validate`, `to_json` and `from_json` take `Limits`.
- `ObservationClock` has `Unknown`, `SourceLabel` or `IngestionLabel` policy,
  optional clock ID and optional reported uncertainty in nanoseconds. Unknown
  policy cannot assert an ID or accuracy. Missing uncertainty is null, not zero.
  A known policy does not require a known clock ID or a timestamp. Reported
  uncertainty, including explicit zero, is a caller label, not measurement.
- `SourceBatch` requires a nonempty batch ID, a lowercase 64-hex-digit SHA-256,
  or both. Its byte length is optional. All supplied identity components
  participate; neither hash nor batch ID authenticates a source. Unknown values
  are never wildcards matching known values.
- `SourceRange` is an ordered half-open source interval with an optional digest.
  It is not a packet span. Empty/inverted/out-of-batch ranges are rejected;
  duplicates, overlaps and reordered intervals remain in input order. Hashes
  describe asserted source identity; this API has no source bytes to verify them.
- `normalize_with_context(ImportedRouteObservation, ImportContext, &Limits)`
  validates both objects, including exact equality of their source/session/
  peer/local labels, and returns one route-evidence envelope. A record ID comes
  from the observation. Generation and direction must agree with the context.
- `normalize_boundary(ImportContext, GenerationBoundary, record_id,
  observed_at_ns, &Limits)` returns a route-free, caller-asserted boundary.
  `GenerationBoundary` contains a previous generation and a nonempty reason.
  The context must name exactly its checked successor and have no direction.
  This is not a BGP NOTIFICATION. It introduces no route or transaction.

Public context types are caller-owned data. Parsing/normalization methods bound
that data before retaining or serializing it. A consumer obtains validated,
immutable context through `bgp_state::Observation::import_context()` and its
boundary through `import_boundary()`; it cannot mutate a retained observation.

## Compatibility and output migration

`bgp::normalize_imported` keeps its signature and observation struct. It now
validates metadata, canonical IP-prefix input and bounded path collections
before allocating its normalized tree. New legacy output sets `generation`,
`direction`, `import_context`, `import_boundary` and wire `evidence` to null.
There is no invented source version, checkpoint, clock accuracy or generation.
The absence of the whole context means every context-specific field is unknown.

`Observation::from_normalized` continues to read older envelopes with no import
context fields and a generation-zero placeholder. That placeholder is treated
as unknown, not as captured generation evidence. Explicit legacy `ImportScope`
remains supported, with its previous behavior. It does not supply batch, version,
clock or checkpoint identity. It is unsuitable for mixing multiple unknown
batches; use the contextual API to establish isolation. Legacy contexts and
contextual partitions never merge.

Both captured and imported route envelopes gain additive `import_context` and
`import_boundary` fields. Captured values are always null; non-null import
metadata on captured evidence is rejected by the state consumer. Existing
captured decoding, capability handling, packet witnesses and reduction policy
are otherwise unchanged. The added null fields change encoded output/event
hashes. Strict schema consumers must allow these optional fields and nullable
imported generation; do not relabel or rehash previous producer artifacts.

No new CLI switch, automatic state reduction, streaming confirmation behavior,
UDP pairing, generic transaction or vendor adapter is introduced. Existing BGP
CLI output receives the normalization's additive null fields only. The separate
candidate-state schema remains v1 with additive `import_partition` on route and
session views, plus `reachability_established=false`. Public `CandidateRoute` and
`SessionView` gain this field; exhaustive external Rust literals need updating.
The old `Source`, `ImportedRouteObservation` and `ImportScope` shapes are retained.

## Reduction and replay contract

For contextual imports the session namespace is:

`(source kind, source ID, session, source schema/version, batch ID/hash/length,
checkpoint ID, peer/local labels)`.

The typed `ImportPartition` is exposed on each candidate route/session. Generation,
direction and exact prefix remain separate dimensions of active route state.
Captured and legacy input use a null partition and keep their existing semantics.
Different batches, changed hashes, changed checkpoint IDs or changed schema/
peer/local context are **distinct namespaces**. No preferred source wins, and a
withdrawal in one namespace cannot remove a route in another. A new checkpoint
starts an independent view; it does not infer that an older checkpoint was
withdrawn, completed or superseded. Old views remain explicitly partitioned.
Callers must not present their union as one authoritative RIB.

The first scoped record supplies an initial generation. Further new records in
that same partition must keep it. Only an explicit exact-successor boundary can
advance it and retire both directions. The reducer checks that the predecessor
exists, matches, and is not identity-conflicted. Missing, backward, skipped,
overflowing or cross-checkpoint predecessor transitions return a typed error
before mutation. A late new record cannot reopen an old generation. An observation
with unknown direction does not create or advance an active session.

Replay identity is `(source kind, source ID, session, import partition, record ID)`.
The full canonical record is compared, not just a digest. An identical replay
returns `IdenticalReplay` with no journal/counter/snapshot mutation, even after a
reset. Its old effects are not replayed. Record IDs must uniquely identify immutable
records within the partition; reassigning one to another direction, timestamp,
clock policy, provenance, path or other content produces identity conflict (or
an invalid-generation error if it violates the current boundary first).
Use distinct record IDs for different records and boundaries.

Conflicting record alternatives retain the existing conservative quarantine
policy, limited now to their partition. A suspect boundary cannot clear that
quarantine. Repetition is never a vote. Distinct records with conflicting path
attributes remain alternatives. Clocks do not choose partners, sort records,
select a generation or expire routes. State application is caller order only.

## Connecting the APIs

```rust
use pcap_evidence::Result;
use pcap_evidence_product::deep::{bgp, bgp_import, bgp_state, Limits};

fn apply_import(
    input: bgp::ImportedRouteObservation,
    context: bgp_import::ImportContext,
    state: &mut bgp_state::CandidateState,
    limits: &Limits,
) -> Result<bgp_state::ApplyOutcome> {
    let normalized = bgp_import::normalize_with_context(input, context, limits)?;
    let observation = bgp_state::Observation::from_normalized(&normalized, None, limits)?;
    state.apply(observation)
}
```

Pass the output of `normalize_boundary` through the same constructor/application
seam before the next generation. Do not pass `ImportScope` alongside full context;
that would create two competing scope authorities and is rejected, even if equal.
These examples are API guidance; the focused native tests and the complete
local Windows gates are recorded in `VALIDATION.md`.

## Bounds and atomic failure

Existing `deep::Limits` own all bounds; there are no added quotas or dependencies.
Identity strings are nonempty, not whitespace-only, control-free and at most
`min(1024,input_bytes)` UTF-8 bytes. Hashes are exact lowercase SHA-256 text.
Metadata totals and typed path collections are preflighted before JSON creation.
`elements` caps variable route/path collections and provenance count;
`spans` also caps aggregate retained imported range references. `fields`, `depth`,
`input_bytes` and `work` bound tree nodes, nesting, strings and validation passes.
The completed normalizer JSON must fit both `input_bytes` and `output_bytes`.

Candidate admission rechecks context against the reducer's limits, even if its
observation was made under larger limits. Existing aggregate observation, route,
span, active-partition, retained-byte and per-apply work/output budgets remain in
force. Validation uses a fixed number of individually bounded traversals; logical
work units are not exact CPU instructions. Staging trees and clones can coexist;
these are not OS-enforced RSS or timing guarantees.

All normalizer failures return before publishing a value. State application
validates and stages its entire journal reduction/output before committing. Any
error, including malformed input, invalid transition or exhausted budget, leaves
the previous snapshot and evidence intact. Imported provenance stays in the
normalized journal and is never relabeled as wire `evidence`.

## Review of the accepted integration

This was not a clean review. The prior consumer's imported namespace lacked batch,
checkpoint, source schema/version and clock context; legacy normalization emitted
a placeholder generation and did not bound the direct imported API consistently.
This slice fills those gaps without changing captured route semantics. The
consumer also rejects optional top-level RIB, best-path, reachability, source-
authority or normative claims unless absent or false; its previous guard checked
only endpoint state and causality. Tests add
context validation, compatibility, immutable replay, changed partitions, explicit
boundaries, clock uncertainty, provenance retention and atomic failure.

The review preserves the accepted fixes for real payload digests, absent direction,
checked generation increments, duplicate-attribute diagnostics and attribute-local
multiprotocol parsing. It does not claim those previously accepted tests passed
again in this worker. Existing producer and consumer tests are not removed.

The producer now stages OPEN state and applies direct output/work/retention
accounting atomically, so those two earlier findings are repaired. At this
review checkpoint, the remaining findings included validation of arbitrary
captured metadata directions, complete two-sided capability/session
adjudication, standards-specific duplicate dispositions, reliable sink boundary
and generation forwarding before automatic state wiring, source authentication,
and actual imported-byte verification. Later producer work implements ordinary
duplicate and repeated-MP RFC 7606 dispositions; the other boundaries remain
separate and are not established by imported normalized data. The
reducer still checks normalized structure, not the truth of its producer's facts.
None of these is silently upgraded by a context hash, timestamp, checkpoint or
successful parser return.

## Focused tests and qualification

`product/tests/bgp_import.rs` contains 33 native tests. The independent
`product/tests/bgp_import_vectors.py` checks eight synthetic identity/transition
vectors; it does not execute Rust. The focused tests, the existing BGP state and
producer tests, product release checks, workspace checks, release Clippy and
the root/product validation drivers all passed on the local Windows checkout.
That is native Windows acceptance for this reviewed tree, not platform/runtime,
live, scale, sustained-fuzz, secure or normative proof.
