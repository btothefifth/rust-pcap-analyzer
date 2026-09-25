# Bounded BGP candidate route state

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

## Atomic ordered replay wrapper

[BGP_REPLAY.md](BGP_REPLAY.md) adds a separate feed owner around this reducer.
`CandidateState` gains `Clone` solely as an additive staging capability; its
private fields, normalization, generation, withdrawal, replay and quarantine
semantics are unchanged. No existing consumer is automatically rewired.

The wrapper checks ordered cursor/record identity and explicit feed completion,
stages whole pages, and publishes only after complete output checks. Its guarded
candidate view is unavailable after a changed ordered record; the full alternative
evidence remains in replay receipts. Historical indices are not selected winners.
Replaying an old record after reset never reapplies its effects. Native execution
of the replay wrapper is a separate outstanding acceptance gate.

## Read-only downstream association seam

[BGP_ASSOCIATION.md](BGP_ASSOCIATION.md) describes the separate opt-in
`deep::bgp_association` API. `RouteBatch::from_candidate_state` borrows a snapshot,
preserves active and inactive journal witnesses and boundary notes, and records
the exact snapshot hash. It neither applies nor changes a route observation.
Inactive, quarantined and conflicting records cannot become a unique current
candidate merely because the active-route view is empty. Native state partition,
replay, generation, withdrawal and quarantine contracts below are unchanged.

Association is caller-policy compatibility only, not RIB, best-path,
reachability, attack, causality or source authority. Batch/checkpoint partitions
remain visible and never merge; the union of candidates is not an endpoint RIB.
The worker did not have Rust tooling and therefore did not run the new native
tests. The integrator ran them, plus the complete product/workspace gates, in
the local Windows checkout; historical state/import receipts do not replace
that fresh evidence.

## Imported-context extension

[BGP_IMPORT.md](BGP_IMPORT.md) is the controlling extension for contextual imports
based on `1de3c4f4b30a67eea8ee752144b39867995bb51a`. Contextual namespaces add
source schema/version, immutable batch/hash/length, checkpoint and peer/local
identity. Explicit successor boundaries are required after the first generation.
A changed batch/checkpoint is a distinct view, not continuation of an old RIB.
Record identity within a partition is immutable: changed content conflicts;
identical replay never reapplies old effects. Route/session views expose their
typed `import_partition`, and observations expose their validated context.

The legacy `ImportScope` and captured reduction rules described below remain
unchanged; the namespace and implicit higher-generation policy there apply only
to those legacy/captured paths. New legacy normalizer output uses null generation,
not the historic zero placeholder (which remains accepted as unknown on input).
See BGP_IMPORT.md for bounds, migration and exact boundary/replay behavior.
The worker could not run native Rust checks; the integrator subsequently ran
the native checks for this extension in the complete local Windows checkout.

Base reviewed: `9522078ffaa698602f664fbf3365e00733ad6951`.

This is an **opt-in source candidate** with local Windows native acceptance for
the reviewed tree. Earlier Windows receipts describe the accepted baseline;
the fresh extension-specific evidence is recorded in `VALIDATION.md`.

## Ownership and non-authority

`pcap_evidence_product::deep::bgp_state` consumes the existing normalized
`pcap-evidence.bgp.route-evidence.v1` value returned by `deep::bgp::decode_pcap`
or `deep::bgp::normalize_imported`. It does not parse another BGP wire format,
reimplement a session decoder, select a best path, reconstruct an endpoint RIB,
or authenticate a source. There is no external service, adapter, cross-source
join, new dependency, new CLI switch, or automatic change to existing event,
NDJSON, TLV, history, DNP3 or generic transaction output.

Its separate output schema is `pcap-evidence.bgp.candidate-state.v1`. The output
sets `endpoint_state_established`, `rib_established`, `best_path_selected`,
`causality_established`, `source_authority_established` and
`normative_conformance_certified` to false. Issues state that input provenance is
inherited and attribute tokens are opaque. Neither these fields nor hashes make
untrusted input authoritative.

The consumer checks normalized structure, exact integer shapes, prefix identity,
source-span coverage and range bounds. A supplied complete semantic-identity
sidecar is additionally checked against the route key and corresponding
normalized attributes, as well as its domain-framed fingerprint. Captured Large
Communities are checked against their first retained type-32 occurrence. The
MRT route projection does not currently carry Large Communities separately, so
that imported identity field cannot yet be cross-checked against a second
normalized representation. These checks reject internal envelope disagreement;
they **do not re-read packet bytes** or prove that a producer's decoded
attribute, prefix, timestamp or digest describes those bytes. Callers must
supply source-verified producer output and maintain its capture/run binding.
`captured` remains the producer's provenance label; `imported` never becomes
packet-derived evidence.

AS4_PATH (type 17) and AS4_AGGREGATOR (type 18) are still treated as opaque by
the semantic-identity sidecar. The BGP normalizer can expose its old/new ASN
reconstruction, but that reconstruction does not make the sidecar complete:
the state consumer marks the route's attributes ambiguous and does not treat it
as a complete semantic identity. Full source-bound identity validation for
those reconstructed attributes remains open work.

## Public API

- `Observation::from_normalized(&Json, Option<ImportScope>, &Limits)` validates and
  freezes an observation. `source()`, `kind()`, `routes()`, `normalized()` and
  `sha256()` are read-only accessors. The digest identifies the canonical
  source/kind/normalized wrapper, not authenticated source bytes.
- `ImportScope { generation, direction }` supplies explicitly asserted scope for
  an imported observation. The original normalized envelope remains unchanged:
  its placeholder generation zero and absent direction are not silently upgraded
  into observed facts. Without this argument, imported generation and direction
  stay unknown. A missing session is never synthesized. Supplying an imported
  scope for a captured record is rejected.
- `Source` preserves kind, source/record ID, optional session, generation,
  direction, timestamp and peer/local labels. Labels are not parsed as evidence
  of endpoint roles. Identifiers must be nonempty, control-free and at most 1024
  UTF-8 bytes; unknown session/direction/time is represented by `None`.
- `RouteObservation` exposes a typed `PrefixIdentity`, optional negotiated
  ADD-PATH identifier, `RouteAction`, the complete
  normalized attribute object, the exact original message-relative prefix range,
  and a duplicate-attribute ambiguity flag. Original attribute ranges, hashes,
  packets and timestamps remain in `normalized()` rather than being rewritten.
- `Observation::reset(Source, reason, evidence, &Limits)` creates an explicit
  caller boundary, separately labeled as not a wire NOTIFICATION. Require a
  session, a next generation, no direction and a nonempty reason. It resets only
  that source-kind/source-ID/session. Its evidence is bounded caller-supplied
  context, not a new claim of wire verification.
- `CandidateState::new(Limits)`, `apply(Observation)`, and
  `apply_batch(IntoIterator<Item = Observation>)` own one bounded journal.
  Successful application returns `ApplyOutcome` or one receipt per batch input;
  any error leaves the entire previous snapshot unchanged. Homogeneous
  context-free and contextual batches validate and reduce once; contextual
  session generation and boundary transitions are still checked in caller order.
  Batches mixing contextual and legacy observations use the sequential validator
  on a staged copy, with aggregate work bounded before publication.
  `observations()`, `outcomes()`, `sessions()` and `routes()` expose
  immutable typed views; `encode()` borrows the already bounded deterministic
  JSON snapshot. `retained_bytes()` is logical accounting, not RSS.
- `last_work()` exposes deterministic logical work units consumed by the latest
  successful apply call, not elapsed CPU time or allocator/RSS measurements.

### Connecting captured decoding without partial decoder-state commits

Use one `bgp::SessionState` for each caller-established source/session. The
candidate consumer is independent and can contain several isolated sessions.
This wrapper stages the existing decoder's mutation until candidate admission
succeeds; it does not alter either decoder's public output:

```rust
use pcap_evidence::{provenance::EvidenceBytes, Result};
use pcap_evidence_product::deep::{bgp, bgp_state, Limits};

fn apply_captured(
    bytes: &EvidenceBytes,
    metadata: bgp::PcapMetadata,
    decoder: &mut bgp::SessionState,
    candidates: &mut bgp_state::CandidateState,
    limits: &Limits,
) -> Result<bgp_state::ApplyOutcome> {
    let mut next_decoder = decoder.clone();
    let normalized = bgp::decode_pcap(bytes, metadata, &mut next_decoder, limits)?;
    let observation = bgp_state::Observation::from_normalized(&normalized, None, limits)?;
    let result = candidates.apply(observation)?;
    *decoder = next_decoder;
    Ok(result)
}
```

This example is authored integration guidance, not executed Rust evidence.
Supply explicit source/session/direction when known. Do not feed incomplete or
error envelopes to the consumer as successful normalized records. Do not share
one decoder across unrelated sessions. On a gap, window boundary, reset, budget
cut, source change or decoder recreation, stop or explicitly establish a new
source/session/generation scope. Forward boundaries before subsequent records.
A normalized numeric generation alone cannot detect an omitted producer reset.

For an imported value, call the same constructor with
`Some(ImportScope { generation, direction })` only when the caller can identify
that scope. Peer strings, timestamps and source preference never supply it. This
API deliberately provides no adapter that invents this context.

## Reduction policy

The namespace is `(source kind, source ID, session)`. `captured` and `imported`,
and distinct source IDs, are independent even if their prefix/path labels agree.
A current route key additionally includes generation, direction, AFI, SAFI,
prefix length and canonical address. IPv4/IPv6 unicast/multicast address-prefix
keys are supported. Other AFI/SAFI forms are retained with
`unsupported_prefix_semantics` but cannot announce or withdraw candidates.
Nonzero host bits and invalid IP lengths are rejected, not silently masked.
Different textual IPv6 spellings get one canonical key; original spelling stays
in the source envelope. A present ADD-PATH identifier is part of the candidate
and withdrawal key, so withdrawing one path cannot erase another path for the
same prefix. An absent identifier remains explicitly absent; unresolved ADD-PATH
layout never reaches this reducer as a guessed prefix. VPN, label or other
unsupported NLRI semantics is not guessed.

Observations are applied in **caller order**, not timestamp or packet-number
order. A higher explicit generation retires both directions of the previous
session generation; the session view names the journal witness for that change.
Lower generations are `late_generation` and cannot reopen or withdraw from the
current generation. Generation numbers never wrap or saturate. A NOTIFICATION
closes exactly the generation carried by that observation, clears its candidates
in both directions, and does not invent a next generation. Later observations in
that closed generation remain `closed_generation`. A higher generation can
start fresh. An explicit reset must advance; a nonadvancing reset is retained
without affecting candidates. Unknown scope cannot advance an existing scope.

Within that generation and direction, an announcement adds its path as a
candidate. Identical attributes in a **different source record** retain another
witness, with `repeated_announcement`; they are not votes. Different attributes
remain ordered alternatives with `conflicting_attributes`, even when one is
numerically preferable or occurs more often. Paths are compared as exact
normalized objects plus ordered attribute identity tokens. Object-key order is
canonicalized; arrays, including AS segments and community order, are preserved.
Attribute source offsets are not path identity, but their original ranges remain
in the journal. Unknown attribute/range fields participate in identity.

A distinct withdrawal removes only its exact current route key; a withdrawal
without a candidate produces `withdrawal_of_absent_candidate`. Old observations
are not deleted. One normalized record containing both actions for a prefix
produces `ambiguous_actions_in_record`, not an invented within-record winner.
Duplicate routes within a record retain all route-index witnesses. Duplicate path
attribute type codes cannot become a single clean candidate from a normalizer's
last-scalar-value representation: they mark its path ambiguous. A later distinct
withdrawal or new generation can retire ordinary path alternatives.

### Replay versus record-identity conflict

Replay identity uses source kind, source ID, session and record ID. Captured
records additionally use their exact ordered packet/span locator. This is
necessary because the existing depth sink uses a content hash as record ID:
identical wire messages observed in different packets are not replay of the same
record. Imported records have no packet locator and rely on caller record IDs.
There is no imported-versus-captured preference and no cross-source merge.

An exactly identical normalized observation and asserted scope returns
`identical_replay` without adding a record, incrementing a count, changing JSON,
or reapplying an earlier withdrawal/reset. Full canonical content, not a hash
alone, is compared. A replay receipt makes no new statement that its old route
is still active.

If one record identity carries differing data, all alternatives remain in the
journal. The affected source/session is quarantined across this consumer's
retained history: earlier and later outcomes become `record_identity_conflict`,
and no active winner is shown. This is deliberately conservative; a suspect
withdrawal or reset cannot retroactively authorize a selection. This ambiguity
does not affect other sources/sessions. It is not silently cleared by reusing a
new generation label. Re-establish a genuinely distinct caller scope for recovery.
Earlier receipts are historical; consumers must use the latest snapshot and its
reclassified outcomes, not cache a prior candidate as permanent truth.

## Limits and failure boundaries

The existing `deep::Limits` are reused without a new configuration file:

| Limit | Consumer meaning |
|---|---|
| `input_bytes` | Maximum serialized normalized envelope; reset evidence and complete reset envelope are also bounded |
| `fields`, `depth` | Total JSON nodes per observation, width and nesting checks before recursive canonicalization/encoding |
| `elements` | Maximum retained observations and aggregate route records, including withdrawn, stale and unresolved records; current candidates and their witnesses cannot exceed the aggregate |
| `spans` | Aggregate retained captured span and packet references, including records no longer active, plus explicit top-level span/packet lists in reset context |
| `active` | Retained source/session generation markers, including closed or quarantined sessions; no silent eviction |
| `retained_bytes` | Canonical source/kind/normalized journal bytes plus exact serialized snapshot bytes |
| `work` | Per-call logical scan, copy, comparison and reduction budget; `apply_batch` accounts for the complete batch rather than resetting per record |
| `output_bytes` | Exact encoded snapshot limit, tested before commit |

Single-record and homogeneous-batch work are computed against a bounded journal.
Indexed identity admission and derived-state reduction each visit the combined
journal once for context-free and contextual batches; mixed batches retain the
ordered staged validator. Logical byte/work budgets are
not allocator-level RSS or CPU-time guarantees. Input trees, staging clones,
typed views and serialized data can coexist. Temporary memory is also bounded by
these finite counts and byte limits, but no measured peak-RSS claim is made.
Repeated replay need not consume retention. It still consumes bounded validation
and comparison work. Quotas never produce partial success or hidden eviction;
callers must record the error and stop/cut rather than continue after discarding
state. Malformed input remains caller-owned and is returned as a typed error; it
is not inserted as an allegedly valid observation.

## Accepted-baseline review and remaining risks

The review included `deep/bgp.rs`, `deep/sink.rs`, the BGP unit tests,
`tests/pcap_depth_cli.rs`, the shared JSON/provenance/limits contracts and the
current product docs. The following issues were found and repaired in the
isolated candidate before acceptance:

1. Path and NOTIFICATION payload fields now use `hex(digest(payload))`, with
   regression tests that distinguish a digest from raw hexadecimal bytes.
2. Missing direction metadata no longer mutates direction-zero decoder state;
   the output records the unresolved condition and uses the conservative
   two-octet ASN parsing default for that message. Generation increments now
   fail closed instead of saturating.
3. MP_REACH/MP_UNREACH headers and next-hop/SNPA boundaries are checked against
   the enclosing attribute. Invalid next-hop lengths, nonzero unsupported SNPA
   entries and truncated neighboring bytes are rejected before route output.
4. Duplicate path-attribute types remain range-visible and report
   `duplicate_path_attribute_type`. Later ordinary attributes carry
   `discard_later_occurrence`; the first occurrence remains the only semantic
   candidate, subject to validation, and state is not ambiguous solely because of that discarded
   duplicate. Repeated MP_REACH_NLRI/MP_UNREACH_NLRI instead carries
   `session_reset` and suppresses route actions.

The following qualification and design limits remain open:

5. The producer now stages state and consistently applies its declared direct
   byte/span/work/output limits. This does not qualify allocator RSS, wall-clock
   CPU, or every downstream consumer's independently declared limits.
6. The sink uses content-derived record IDs and can clear BGP decoder state on
   boundaries or budget cuts. The consumer's packet-locator replay key addresses
   occurrence identity, but automatic sink wiring would require reliable boundary
   forwarding and generation management. It is intentionally deferred rather
   than changing accepted output implicitly.
7. Existing BGP docs and the real-PCAP test describe/check normalized evidence,
   not a typed route-state API or reducer limits and conflicts. This document,
   status/depth pointers and the new native tests fill that consumer gap. Existing
   tests and producer schemas remain additive; no authority claim is introduced.

This addition does not certify complete normalized path semantics or full BGP
conformance. The next producer work is broader capability/session adjudication
and explicit integration of source/window/generation boundaries. The reducer remains
an opt-in candidate-state consumer, not an endpoint RIB or best-path engine.
Separate future work may add an explicitly versioned consumer integration that
forwards every source/window/generation boundary. Do not infer it from this API.

## Test vectors and current evidence

`product/tests/fixtures/bgp_state.hex` contains five manually laid-out wire
messages. The UPDATE announcement is 45 bytes: 19-byte header, two zero withdrawal
length bytes, two attribute-length bytes, 18 attribute bytes, four prefix bytes.
The attribute extents are `[23,27)`, `[27,34)`, `[34,41)` and the prefix is
`[41,45)`. Values are ORIGIN 0, AS_SEQUENCE `[65000]`, next hop `192.0.2.1`, prefix
`203.0.113.0/24`. Withdrawal length is 27 bytes. NOTIFICATION length is 23 bytes,
with code/subcode 6/2 and two data bytes. KEEPALIVE is 19 bytes. The duplicate
ORIGIN UPDATE is 49 bytes and deliberately retains both attribute witnesses.
These are synthetic byte vectors, not captured endpoint behavior.
`python product/tests/bgp_state_vectors.py -v` runs six independent Python
fixture-arithmetic checks. They passed in the worker and locally; they do not
execute the Rust normalizer or the new consumer.

The native suite includes direction/source/session/AFI/SAFI isolation, absent
withdrawals, generation/notification/reset behavior, replay after reset,
conflicting attributes/identities, missing scope, unknown attributes, duplicate
routes, exact split-packet spans, limits and deterministic JSON. Those tests,
the full product debug/release matrix, workspace debug matrix, Clippy, root
validation, and portable product validation passed locally for the reviewed
tree. Product/streaming Linux runtime, live, scale, sustained fuzz, external
corpus and normative gates remain open for this candidate.
