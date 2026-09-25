# Bounded BGP candidate evidence association

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

## Replay-aware receipts and coverage

[BGP_REPLAY.md](BGP_REPLAY.md) adds a separate ingestion/replay seam. Its
`association_receipt` calls the existing read-only snapshot adapter while meeting
caller coverage with feed completion and every retained record's coverage.
Partial feeds stay incomplete, and finality never upgrades unknown coverage.
Quarantined feeds return a typed error with their full replay receipt still
available; no old candidate view is exposed through that adapter.

The receipt preserves ordered normalized records, source/batch/checkpoint,
generation, clock labels, provenance and the candidate snapshot hash. Pass its
`routes()` to `associate` and keep its `encode()` beside the association result.
Namespace/flow context and policy remain explicit caller inputs. This does not
change association matching, infer clock or namespace equivalence, authenticate
external data or wire a production join. The new wrapper's native tests have not
been executed by the authoring worker; prior association acceptance is historical.

`pcap_evidence_product::deep::bgp_association` is an opt-in, read-only association
seam over normalized BGP observations and independently produced internal flow
or security records. Its output schema is `pcap-evidence.bgp.association.v1`;
its evidence wrapper is `pcap-evidence.association-input.v1`. A structural output
schema is supplied in `bgp-association.schema.json`. Neither schema verifies a
producer, a packet, an internal event, or a correlation policy.

**Locally native-accepted on Windows; not production-qualified.** The authoring
worker executed eight independent Python vector tests but had no Cargo, rustc,
rustfmt or Clippy. The integrator then applied the complete patch in an isolated
checkout and ran the 40 Rust association tests, workspace and product checks,
release product coverage, Clippy, the Python vectors and the repository
validators. Linux/macOS runtime, live, scale, fuzz, security and normative
qualification remain open.

## Scope and authority

This API relates evidence dimensions selected by an explicit caller policy. It
is not an endpoint RIB, best-path engine, routing simulation, reachability test,
attack detector, source authenticator, or causal inference engine. All output
claims for endpoint state, RIB, best path, reachability, attack, causality, source
authority and normative conformance are explicitly false.

There is no network access, source-specific parser, external ingestion adapter,
credential handling, database, automatic sink/CLI integration, generic transaction
change, or alteration of BGP/DNP3 decoding. Imported BGP remains caller-adapted
through `bgp_import`. The new seam does not apply or replay observations into a
`CandidateState`; it only borrows validated observations or an existing snapshot.

Source verification, redaction of sensitive caller metadata, namespace mapping,
clock comparability, coverage declarations and production association remain the
caller's responsibilities. In particular, a syntactically valid hash is not proof
that the named source contains the claimed bytes. Captured provenance remains
inherited from the existing producer. Internal provenance is independently shaped
caller data, never synthesized packet evidence.

## Typed input APIs

- `RouteEvidence::from_normalized(&Json, route_index, &RouteContext, &Limits)`
  first uses the existing `bgp_state::Observation` validation seam. The
  `from_observation` alternative accepts a previously constructed observation
  and rechecks the new consumer's limits. Each route keeps its full normalized
  envelope, original route index, attributes, packet/source ranges, hashes,
  source/record identities, native session/generation/direction and import context.
- `RouteContext` supplies an association namespace, optional flow identity,
  optional captured/legacy clock labels and explicit coverage. It cannot replace
  a contextual import's clock, generation, direction, checkpoint or source batch.
  Even an equal supplied clock override is rejected for contextual imports.
  Legacy imports without immutable context are retained with
  `missing_import_context`; the seam cannot establish which batch they describe.
- `InternalEvidence::new(InternalInput, &Limits)` freezes an independently
  produced `Flow` or `Security` record. `SourceIdentity` holds source/record ID,
  schema/version and optional batch/checkpoint. `Dimensions` holds an explicit
  namespace/session/generation/flow/direction scope, optional prefix and IP
  endpoint, plus explicit unsupported-dimension labels. `TimeLabel` holds an
  optional signed nanosecond label and `ObservationClock`. `Provenance` retains
  an optional record digest, ordered source-relative ranges and opaque details.
- `RouteBatch::new` bounds a supplied collection of route observations.
  `RouteBatch::from_candidate_state` takes an immutable state reference and
  records the exact snapshot digest. It retains active route witnesses,
  inactive/withdrawn/quarantined observations, and route-free boundary/metadata
  witnesses. An inactive row is not a current candidate. Retired attributes do
  not compete with current paths; relevant prior evidence is not erased.
- `associate(&RouteBatch, &[InternalEvidence], &Policy, &Limits)` returns an
  immutable `AssociationReport` only after all validation, comparison, canonical
  output and budget checks succeed. Its `routes`, `internal`, `associations`,
  `notes` and `encode` accessors expose typed outcomes and the bounded result.

The source structures use optional values where knowledge can be absent.
Missing session, direction, timestamp, clock ID or uncertainty is never replaced
with an invented zero, default peer, first record or source-specific assumption.
Namespaces must be explicitly established by the caller, not inferred from a
source ID, IP address, port, path attribute, timestamp or similar spelling.

For example, connect an existing candidate snapshot without mutating it:

```rust
use pcap_evidence::Result;
use pcap_evidence_product::deep::{bgp_association as association, bgp_state, Limits};

fn inspect_snapshot(
    state: &bgp_state::CandidateState,
    context: &association::RouteContext,
    internal: &[association::InternalEvidence],
    policy: &association::Policy,
    limits: &Limits,
) -> Result<association::AssociationReport> {
    let routes = association::RouteBatch::from_candidate_state(state, context, limits)?;
    association::associate(&routes, internal, policy, limits)
}
```

A normalized `bgp::decode_pcap` result can instead pass directly through
`RouteEvidence::from_normalized`. This path describes an observation, not an
assertion that its route remains active. For active-state context use the snapshot
adapter. Do not share captured decoder state across unrelated sessions; the
captured decoder's existing staging and boundary-forwarding requirements remain.

## Explicit comparison policy

There is deliberately no `Policy::default()`. Every call supplies a policy ID,
spatial rule, session/generation/flow requirements, direction rule and time policy.
Association namespace equality is always required. Missing namespaces are
unresolved, not wildcards; distinct known namespaces are incompatible.

`DimensionRule` either ignores the named dimension explicitly or requires equal
known values. Ignoring session/generation/flow labels does not merge the source
records: all original identities and immutable import partitions remain visible.
Direction is explicitly ignored, equal or opposite. Numeric direction and
session/generation labels are comparable only under the caller's declared common
namespace and dimension policy; the API does not infer a mapping between them.

Spatial comparisons support exact canonical IPv4/IPv6 unicast prefix equality,
or membership of an internal IP endpoint in a BGP prefix. Membership compares
address bits only. It says nothing about next-hop traversal, packet path, route
installation or reachability. IPv4-mapped IPv6 remains a distinct address family.
Noncanonical prefixes, excessive prefix lengths and malformed known-family IP
addresses are errors. Other AFIs/SAFIs and declared unsupported dimensions remain
unresolved and retained, not guessed. Ports, MAC addresses, NAT, tunnels,
add-path/VPN/label relations and application-specific security semantics are not
implemented dimensions.

### Time-window semantics

`TimePolicy::Ignore` requires a nonempty reason and records that time was not
used. It does not fabricate distance or accuracy. `TimePolicy::Window` uses an
inclusive, symmetric absolute nanosecond-distance window. It never imposes packet
order, event order, causality or an expiry policy.

Clock relation must be either the same non-unknown clock policy and clock ID,
or an explicit caller-comparability assertion with a nonempty basis. Different
source/ingestion label policies are not automatically equivalent. A missing clock
ID or unknown policy remains unknown even under a comparability assertion.
Missing timestamps, unknown clock identity and required-but-unknown uncertainty
produce typed unresolved reasons, or an atomic error under `MissingClockHandling::Error`.

`LabelDistance` compares only `abs(t_route - t_internal)` and explicitly does not
use reported uncertainty. Unknown uncertainty stays null. `AllReportedBounds`
requires both uncertainty labels. With distance `d`, reported uncertainties
`u` and `v`, and window `w`, the retained possible absolute-distance range is:

- minimum: `max(0, d - u - v)`;
- maximum: `d + u + v`.

A maximum at or below `w` meets this policy. A minimum above `w` is outside the
window. A range that straddles the boundary is unresolved (`uncertain_window`).
These are arithmetic consequences of caller labels, not measured clock bounds.
Intermediate arithmetic uses 128-bit integers; signed 64-bit time extremes and
unsigned 64-bit uncertainty extremes remain exact. JSON uses decimal strings.

## Alternatives, duplicates and unresolved observations

Every route/internal pair is retained within the finite Cartesian budget,
including incompatible and unresolved comparisons. Empty sides receive explicit
`no_route_evidence` or `no_internal_evidence` rows. A returned report never means
that a larger, unprocessed input was silently truncated.

One compatible pair without unresolved conditions is `compatible_candidate`.
Missing dimensions/time, insufficient declared coverage/provenance, unsupported
semantics, duplicate identity, changed content, conflicting attributes, multiple
compatible alternatives and inactive/non-announcement records are unresolved.
Known dimension or clock mismatches and definitely outside-window pairs are
`incompatible`. Reasons are sorted and deduplicated while source arrays and
original ranges preserve their own order. A pair can retain both an incompatible
reason and additional unresolved reasons; no supporting evidence is discarded.

Identical input entries are represented once with an explicit occurrence count
and `duplicate_identity`; duplicates do not increase confidence or select a
winner. Different canonical contents under one immutable record identity retain
all alternatives and mark `changed_content_conflict`. Full canonical contents,
not hashes alone, are compared. Several route indices in one unchanged BGP
record are not a changed-record conflict. Captured identities include the
original packet/span locator so repeated wire occurrences are not collapsed
merely because a producer's record ID is a content hash.

Contextual imported identities include the complete existing import partition:
schema/version, batch ID/hash/length, checkpoint, peer/local plus source/session.
Changing generation/direction on one immutable record is a content conflict;
different batches/checkpoints remain separate records and separate route scopes.
No BGP batch is joined to another batch. The common association namespace merely
permits comparing each separate record with internal evidence under the policy.
Captured/imported/internal sources never gain precedence from their kind.

Different path attributes under the same native source/partition/session/
generation/direction/prefix/path-ID key are conflicting alternatives. The path
ID is included only when the normalized route carried one, preserving classic
non-ADD-PATH native keys. Ordered unknown
attribute identity tokens remain in the comparison and full source envelope.
The candidate-state adapter preserves the reducer's ambiguity and excludes
retired paths from active-path conflict comparisons. No majority, best-path
rule, timestamp sorting or first/last winner is introduced. Multiple plausible
partners on either side remain all present with `multiple_candidates`.

## Determinism, limits and atomicity

Canonicalization sorts object keys and outer evidence entries, not ordered source
arrays, AS paths, ranges or historical observations. Reversing the input arrays
with identical entries produces identical output. This is not a claim that
reordering `CandidateState::apply` operations would leave its state unchanged.
Duplicate occurrence counts are evidence of the supplied input, not votes.

All entry points take existing `deep::Limits`:

| Limit | Association meaning |
|---|---|
| `input_bytes` | Individual wrappers and aggregate serialized policy/input/selection evidence; snapshot adapter also caps its entire source snapshot |
| `fields`, `depth` | Aggregate input nodes and nesting, conservative preconstruction output-node bound, and final output-tree validation |
| `elements` | Input entries, retained route/metadata observations and worst-case Cartesian pairs; the combined output must fit |
| `spans` | Aggregate imported/source-range and captured packet/span references, including boundary notes and duplicates |
| `active` | Native source/prefix comparison keys and independent internal record identities, not real endpoint counts |
| `retained_bytes` | Canonical input representation, internal identity/content keys and final encoded result; logical accounting, not measured allocator/RSS |
| `work` | Bounded validation, key/string comparison, sorting, pair and output work; charged before association publication |
| `output_bytes` | Exact canonical encoded result length |

The shared `Limits::default()` depth is 32 so a captured normalized record can
carry its nested packet-evidence and occurrence witnesses through the association
seam. A caller may lower the depth explicitly; the consumer then rejects deeper
input atomically rather than silently truncating it.

Identifiers are nonempty, not whitespace-only, control-free and at most
`min(1024, input_bytes)` bytes. Hash strings are exactly 64 lowercase hexadecimal
digits. Source ranges must be nonempty, ordered individually and inside a known
batch extent; repeated or reordered ranges are retained as witnesses.
Malformed known dimensions, duplicate JSON keys, unsupported authority claims,
overlong metadata and exhausted budgets produce typed errors. Unknown dimensions
are not mislabeled as malformed simply because this slice cannot interpret them.

The operation is read-only and returns no callbacks or partial iterator. Inputs,
staged trees and encoded results can coexist within finite logical bounds; no
OS-level memory sandbox, peak-RSS, latency or scale guarantee is claimed. On an
error, caller-owned state is unchanged and no report is returned. There is no
hidden eviction or retry with weaker policy. Lower association limits are
rechecked even when inputs were constructed under larger producer limits.

## Accepted-integration review and exact remaining boundary

The imported-context and candidate-state source and relevant tests/docs were
reviewed. This was not a clean review or a complete protocol certification:

1. The prior APIs intentionally did not provide an explicit cross-evidence
   comparison policy or internal-record input. This module fills that bounded
   seam without changing either existing producer or reducer.
2. An active-only view can conceal reset, quarantine or missing-scope evidence.
   The new snapshot adapter retains the inactive journal rows and boundary notes
   and distinguishes them from active witnesses. This does not change the
   meaning of the existing `CandidateState::routes()` accessor.
3. Captured/legacy records do not establish clock comparability or immutable
   imported-batch identity. The new adapter makes those limitations explicit,
   rejects contextual-clock overrides and never supplies a default timestamp.
4. The inherited normalized-state identity helper accepts whitespace-only labels
   and its authority guard does not include an attack-claim key. The association
   boundary rejects whitespace-only identities and recursively rejects positive
   authority/attack claims. The upstream APIs are not changed by this slice.
5. At this association-review checkpoint, direct captured producer budget parity
   and staged OPEN mutation had been repaired, while arbitrary captured direction
   validation, full capability/session adjudication and standards-specific
   duplicate handling remained upstream work. Later producer work implements
   RFC 7606 ordinary-duplicate and repeated-MP dispositions; this association
   module still does not complete all capability/session adjudication or validate
   source authenticity.
6. Source authenticity, actual imported byte verification, reliable automatic
   sink/generation forwarding, operational data and production policy validation
   remain caller/integrator work. A snapshot digest is only an identity for the
   supplied snapshot, not evidence of device state.

The new API deliberately remains more conservative than a production matcher:
missing coverage, unreviewed producer issues, unsupported dimensions and multiple
partners can make all compatible comparisons unresolved. Callers must inspect
reasons instead of treating an empty winner list as proof of absence.

## Tests and qualification

`product/tests/bgp_association.rs` contains 40 authored native tests, including
current normalized and candidate-state adapters, a fixed captured UPDATE,
independently shaped internal flow/security data, exact/containment comparisons,
namespace/session/generation/flow/direction isolation, missing clocks, reported
intervals, signed extremes, input permutations, duplicates/conflicts, retained
provenance, malformed/unsupported dimensions, false authority flags and atomic
limits. It also consumes the fixed time TSV vectors.

`python product/tests/bgp_association_vectors.py -v` executes eight independent
Python checks over nine hand-calculated time cases and seven prefix cases. These
checks passed in the worker and locally; they remain a separate arithmetic
oracle and do not replace the native tests.

The complete isolated patch application, native association tests, workspace
and product matrices, release product coverage, Clippy, root validator and
portable product validator passed in the local Windows checkout. No existing
tests, APIs, dependencies or event contracts were removed or loosened.
Platform/runtime, live/scale/fuzz/security and normative qualification remain
open before any automatic consumer or
production integration. External ingestion is not part of this module.
