# Incremental MRT and source-bound evidence contract

This document defines the incremental MRT source-evidence surface in the
[BGP completion contract](BGP_COMPLETION.md) and preserves the MRT, BMP, and
captured-store contracts. The support matrix declares it as
[BGP-S013](bgp-support-matrix.json). Optional per-field comparison has a native
producer, CLI field, and Python conversion path. Its owning sources are
`product/src/deep/bgp_evidence.rs`,
`product/src/bin/pcap_depth_support/bgp_stream_commands.rs`, and
`tools/research/bgp_compare.py`; owner tests are
`product/tests/bgp_comparison_fields.rs` and
`tools/tests/test_bgp_compare_fields.py`. The finite comparison owner runs
returned 66 Python checks and one native bridge check. The planned root-owned receipt will record executed outcomes and exact source
inventory; local, hosted, and
qualification scopes remain separate. Per-field agreement is not full
route-semantic equality.

## Controlling change contract

The incremental stream path follows one ordinary path: regular MRT input ->
bounded canonical record decoder -> sealed incremental raw-source store -> verified replay ->
ordered checkpoint evidence -> manifest/window export -> attributed external
comparison. Every consequential consumer must retain original source identity,
offsets, dispositions and uncertainty.

Required outcomes are incremental admission beyond the whole-batch 64 MiB
ceiling, explicit source-order chronology across independent checkpoints,
stable evidence manifests with explicit ASN/time selectors, and a bounded
external normalized BGP differential interface. Existing whole-batch limits
and readers remain valid. New input capacity does not remove state-retention
limits or establish measured RSS or throughput.

Forbidden outcomes include resetting decoder context at processing boundaries,
inventing peer-index bytes, changing source/checkpoint identity per buffer,
carrying PIT/OPEN/RIB context across independent sources, sorting by clock
labels, publishing partial output as complete, silently dropping uncertainty,
fabricating packet provenance, and treating comparison agreement as protocol
correctness or candidate admission.

## Raw source and processing boundaries

The additive `PCBMRT02` container stores exact original records. A bounded
header binds labels and admitted length; consecutive frames bind ordinal,
absolute original-source offset, raw length and bytes through a domain-separated
chain. The terminal footer binds complete source SHA-256, byte length, record
count, final chain and seal. Verification rejects truncation, growth, trailing
bytes, discontinuity, duplication, reordering and inconsistent identities.
Digests establish integrity, not collector authentication.

Both whole-batch and incremental readers use the same canonical record grammar.
The actual active peer table retains its original offset and digest through
supported and opaque ADD-PATH RIB series. Unrelated records invalidate it.
Canonical BGP4MP replay retains its bounded OPEN/FSM context within one source.
Whole-source identity is known before normalization: a full verification pass
precedes emitting replay; replay verifies the source again before completing
its receipt. Intermediate sink output remains provisional.

Memory admission covers current record, active peer table, capped session
context and current output row. Source bytes, record size/count, work, retained
state and output each have explicit caps. Disk admission includes original
input, framed store and partial output coexistence. Failure retains an owned
partial workspace for inspection; successful completion publishes the manifest
last through a no-overwrite path.

## Sequence, chronology and windows

`pcap-evidence.bgp.source-sequence.v1` binds each entry's caller ordinal, full
source identity, checkpoint label, store seal and predecessor digest. Sequence
order is evidence-inspection order. Every source is replayed independently;
adjacency never proves wire continuity. Chronology preserves record order,
exact MRT seconds/microseconds, regressions, opaque and rejected records, and
route-free events.

Manifest identity binds source identities and seals, semantic profile and
relationship options, row count/digest and coverage/disposition counts. Paths
are navigation hints. Operational read-buffer sizes do not alter semantic
identity. Row anchors use whole-source identity, absolute record offset/digest
and entry coordinates, never replay-local observation indexes alone.

Coverage counts use rows except `records`, `unknown_mrt_record_time` and
`timestamp_regressions`, which use distinct source records. Regressions compare
adjacent known MRT labels within one sequence entry; an unknown label interrupts
the comparison and an independent source starts a new comparison. Route-free
counts include rows without a nonempty normalized route array. Diagnostic
classes use the first text-valued event `parse_status`, `status` or `kind`, falling
back to `unknown`; `opaque`, `reject`, `quarantin` and `unsupported` substrings
produce overlapping opaque, rejected, quarantined and unsupported row counts.
These summary classes never establish reducer admission. Quarantine retains
unknown interpretation disposition and partial disposition coverage.

New v1 manifests always include additive `coverage.quarantined`, immediately
after `rejected` in the canonical digest payload. A missing legacy field remains
absent when reconstructing the original commitment and cannot prove zero
quarantine. Status witnesses retain the original status; their bounded list is
the source-order prefix of per-row reasons: unknown selector time, unknown MRT
time validity, unknown ASN, then an abnormal diagnostic status. There is one
status witness per abnormal row even when several diagnostic classes match.
`witnesses_truncated` counts every reason omitted after that prefix, including
when the witness limit is zero. Legacy payloads omit quarantine-only witnesses.

ASN selectors use validated effective paths with explicit `path_member` or
`origin` roles. Origin requires a unique supported terminal origin; AS_SET and
unresolved transitions remain unknown. Time selectors require an explicit
clock basis and scope, use exact integer nanoseconds and half-open intervals,
and never substitute ingestion time, zero or a different clock for missing
evidence. Outputs retain unresolved/unsupported witnesses and counts. A label
inside a window does not establish certain occurrence-time membership.
Missing or out-of-range BGP4MP_ET microseconds preserve raw values with unknown
numeric time and precision. This rule also applies to the canonical imported
observation clock, so changing time basis cannot create precision.
These exports inspect historical source observations, without endpoint-current
route installation or reachability claims.

## External comparison

`pcap-evidence.bgp.interpretation.v1` binds attributed producer and adapter
versions, source digest/length, normalization/config identities, numeric source
anchors, tagged imported-source provenance, coverage and typed dispositions.
Ordered raw attribute occurrences, duplicate/discard dispositions and incomplete
semantic identity are preserved. External commands are inert metadata.
Normalized route attributes and semantic identities remain incomplete when the
native identity is missing, unresolved or incomplete. Separately observed raw
attribute evidence can still be compared without making those semantics complete.

The native converter recognizes an otherwise status-free RIB candidate only
when the chronology event has `kind: "rib_entry"`, the normalized observation
uses the exact integer imported carrier `message_type: 0`, and it contains
normalized announcement, prefix and attribute evidence. An unsupported or
opaque record, unrelated carrier-zero observation or wire-type-2 fixture cannot
establish this disposition. Here `accepted` means decoded candidate evidence;
incomplete semantic identity remains incomplete and comparison cannot admit
the route into state.

`pcap-evidence.bgp.differential.v1` compares only matching source identities and
normalization profiles. Missing coverage is `not_comparable`; rejected versus
accepted evidence is a disagreement. Supported matching fields are agreement
within declared coverage. Comparison records `consensus_used=false` and cannot
enter the core admission path.
The exact source range must also match for a joined record/entry anchor. A
framing disagreement about its extent prevents disposition and semantic fields
from voting agreement or disagreement for that observation.

### Optional per-field BGP comparison

`--comparison-fields per-field-v2` on chronology/window export selects
`pcap-evidence.bgp.evidence-row.v2` and
`pcap-evidence.bgp.evidence-manifest.v2`. The default `legacy-v1` mode preserves
the original v1 schemas and conservative semantic completeness rules. Both
modes retain the source-neutral semantic identity profile v2.

The v2 producer constructs `pcap-evidence.bgp.route-field-availability.v1`
from validated native `Observation`/`RouteObservation` values. It binds each
declaration to its sequence/source/store/record/entry reference, ordered route
indexes, exact action, canonical prefix and explicit optional ADD-PATH ID.
Its manifest declares the supported mode and availability schema; the exact
row digest and manifest identity commit these declarations. These hashes
establish carrier integrity, not collector or producer authentication.

The converter requires the matching explicit mode:

```sh
pcap-depth bgp chronology imported/bgp.mrt-stream --workspace chronology \
  --comparison-fields per-field-v2
python3 -B -m tools.research.bgp_compare native chronology/evidence.ndjson \
  chronology/manifest.json --comparison-fields per-field-v2
```

This conversion emits `pcap-evidence.bgp.interpretation.v2` under normalization
`bgp-source-fields-v2`. Its exact `field_coverage.nlri` map names
`route_actions` and `route_prefixes`. The differential uses
`pcap-evidence.bgp.differential.v2`; it compares those fields using their
explicit per-field coverage even when the legacy NLRI group is partial.
A withdrawal or a route with incomplete unrelated attributes can therefore
retain comparable action/prefix evidence. Missing attributes, unknown next-hop
semantics, legacy route aggregates and semantic identities keep their existing
uncertainty. Per-field action/prefix agreement establishes no full route
semantic equality.

A hidden or unresolved NLRI projection prevents complete aggregate
route-action/prefix coverage. A validated family-header-only EOR can retain the
producer's explicit complete empty projection. Unsupported prefix families
remain incomplete. Exact keys, route cardinality/order, source references,
action/prefix/path-ID consistency and projection completeness are checked
before conversion, including rows outside an explicitly selected partition.
Mixed v1/v2 mode, row, manifest, normalization or interpretation combinations
reject. Legacy interpretation comparison remains unchanged.

A saved normalized interpretation is attributed research data; it is not a
replacement for the original NDJSON/source closure. Conversion verifies the
complete original export commitments. Reloaded v2 native interpretations check
the retained declaration/projection/manifest references, but do not replay
omitted original NDJSON bytes. Coordinated replacement of an export and its
self-generated commitments cannot establish source authenticity. Comparison
uses no consensus, admits no canonical state, and establishes no endpoint
negotiation, route installation, reachability, causality, or other operational
conclusions.

## Finite acceptance and remaining qualification

### Reproducible first-disagreement bundles

The existing research commands accept exact-schema BGP v1 or v2 interpretation
peers and retain their comparator's first observed disagreement:

```sh
python3 -B -m tools.research bundle original.mrt native.json external.json \
  --specifications specifications.json --output disagreement.zip
python3 -B -m tools.research verify-bundle disagreement.zip
```

The BGP bundle variant uses the existing archive inventory and no-overwrite
publication. It includes the exact original source, interpretations,
differential, specification references and byte-range witnesses. The source
must match both interpretations; mixed interpretation modes reject. Sources
and individual expanded members are limited to 32 MiB, JSON documents to
8 MiB and both the physical and expanded archive to 96 MiB, including its manifest.
Admission precedes publication; larger sources require a separately scoped
research approach rather than silently omitting source bytes.

The same manifest records reproducible derived-dataset provenance: source and
stored interpretation/differential identities, normalization, and retained
native partition, sequence, window and native-manifest identities when present.
Verification reruns the existing BGP comparator and recomputes those bindings
and first-disagreement byte hashes. Ranges remain producer-declared anchors;
the bundle does not independently map parsed records or replay omitted original
NDJSON. A self-consistent replacement of source and interpretations can remain
reproducible without establishing parser correctness or producer/collector
authenticity. Agreement, disagreement and a passing bundle verification supply
no canonical state admission or protocol qualification.

Owning controls must exercise virtual input above 64 MiB without a large disk
fixture, read splits and truncation, exact caps and one-below rejection, actual
PIT association, canonical BGP4MP continuity, checkpoint isolation, reversed
clock labels, seal/ordinal/source tampering, window endpoints and unknowns,
stable semantic identity across buffer sizes, numeric comparison ordering and
external source/profile refusal. Tiny ordinary CLI fixtures exercise fresh
verified consumers and no-overwrite publication.

Independent source review precedes integration; an additional independent
coherence review checks assembled behavior. Local execution and exact-head
hosted CI remain separate evidence. Real-corpus parity, sustained fuzzing,
representative scale/RSS, complete normative review and broader security
qualification require their own receipts. Resume cursors, unlimited state
history, built-in external subprocess adapters and live feed operation are
subsequent work, not implicit capabilities of this increment.

## Command surface

The additive depth commands use a create-new workspace:

```sh
pcap-depth bgp import-mrt-stream input.mrt --workspace imported \
  --source-id collector-a --checkpoint checkpoint-a
pcap-depth bgp chronology imported/bgp.mrt-stream --workspace chronology \
  --with-store later/bgp.mrt-stream
pcap-depth bgp window imported/bgp.mrt-stream --workspace window \
  --asn 65001 --asn-role origin --time-basis mrt-record \
  --clock-source collector-a --start-ns 1000000000 --end-ns 2000000000
python3 -m tools.research.bgp_compare native chronology/evidence.ndjson \
  chronology/manifest.json --source-ordinal 0
python3 -m tools.research.bgp_compare native chronology/evidence.ndjson \
  chronology/manifest.json --source-ordinal 0 --row-start 0 --row-count 100
python3 -m tools.research.bgp_compare compare native.json external.json
```

Import publishes `bgp.mrt-stream` and `receipt.json`. Chronology/window publishes
`evidence.ndjson`, `sequence.json` and `manifest.json`; the complete manifest is
published last. Window exports retain all chronology rows with selector
dispositions and a selection flag, including witnesses that cannot be resolved.
Partial names remain available after publication as hard links to the completed
files, sharing their allocated storage. Publication performs no pathname
deletion; workspace retirement is a separate owner action.
`--with-store` may repeat and its argument order is the explicit source order.
Relationship configuration for these commands applies uniformly to the selected
independent sources and is recorded as caller configuration.

Time bases are `mrt-record`, `rib-originated` or `observation`; ASN roles are
`origin` or `path-member`. `--clock-source ID` selects an exact source ID,
including a source literally named `all-source-clocks`. The legacy
`--clock-scope ID` selects an exact source except that
`--clock-scope all-source-clocks` explicitly inspects all independent source
labels. These options are mutually exclusive. The all-source selection
never establishes clock synchronization or a common occurrence-time interval.
An exact clock scope must exist in the selected sequence; an absent scope is a
typed refusal, without a completed export. Rows belonging to other admitted
source clocks retain an `outside_clock_scope` disposition.
The API uses `ClockScope::Source` or `ClockScope::AllSourceClocks`; converting a
string into this type always creates an exact source selection. New manifests
bind `clock_scope_kind` (`source` or `all_source_clocks`) alongside the label,
so the two operations have distinct identities even when their labels match.

Stream limits are `--max-source-bytes`, `--max-store-bytes`,
`--max-record-bytes`, `--max-records` and `--max-work`; exports also accept
`--max-output-bytes`. CLI output admission defaults to 64 MiB and has a 256 MiB
ceiling. CLI admission also bounds a source to 8 GiB, a store to 16 GiB, a record
to 16 MiB and record count to ten million. These are command ceilings, not
measured scale qualifications or an aggregate filesystem quota. The local
repository storage constraint continues to cover all project artifacts.

The external interface accepts an independently produced, attributed normalized
document. Each covered field carries an `observed`, `unknown`, `incomplete` or
`unsupported` envelope. Only observed fields with complete coverage on both
sides can agree or disagree. Multi-source exports require an explicit source
ordinal when converting to a single-source interpretation. Commands stored in
producer metadata are never executed.

Native conversion streams and verifies the complete export, admitting up to
256 MiB and 1,000,000 rows. The normalized interpretation remains bounded to
8 MiB and 10,000 observations. For larger exports, use explicit `--row-start`
and `--row-count` to select a source-local row interval after choosing the source
ordinal. The complete requested interval must fit that source's row count;
an interval beyond its last row is refused. Select smaller intervals when normalized bytes exceed the
interpretation ceiling. No implicit truncation or source merging occurs.
The `native_partition` metadata records the half-open row interval, total rows
for that source, source ordinal and whole-export verification, alongside the
complete bound native manifest. Corrupt or incomplete rows outside the selected
interval still prevent conversion. All partitions remain offline attributed
interpretations; their verification does not authenticate the collector.

The converter reconciles all available coverage counts with the complete
export before publishing any partition. Selector unknown counts derive from
the reported row dispositions; conversion does not re-execute the native ASN
validator. It also verifies witness anchors, reasons and ordering against the
bounded expected prefix, and reconciles exact witness truncation. This is
row/summary consistency evidence, without raw-source authentication or broader
protocol qualification. Adapter version 3 carries the additive interpretation
field `native_coverage_verification`: `complete` when quarantine coverage is
present and verified, or `legacy_quarantine_unavailable` for a correctly sealed
older payload. A legacy export still verifies every available counter and
its original witness contract; `whole_export_verified` does not fill the missing
quarantine coverage. Differential output preserves both availability labels in
`native_coverage_verifications` when supplied. Unrecognized parser statuses
retain their original event and unknown/partial disposition interpretation.
