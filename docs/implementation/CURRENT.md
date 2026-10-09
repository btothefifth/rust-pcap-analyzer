# Current implementation pointer

This page points to the active offline BGP surfaces, the current follow-up scope,
and its source-bound receipt. It is navigation, not proof by itself.

## Active BGP surfaces

- Captured BGP framing, source-span provenance, session observation, and
  candidate route-state reduction.
- MRT/TABLE_DUMP_V2 and BGP4MP plus BMP v3 import, sealed source stores, fresh
  replay, and source-scoped route candidates.
- Persisted replay, query, policy, export, source-ordered changes, caller-scoped
  expectations, and association across supported captured, MRT, and BMP stores.
- Incremental MRT admission, chronology, window selection, evidence manifests,
  and bounded attributed comparison.

The [support matrix](../product/bgp-support-matrix.json) links each profile area
to its owning code and tests. The [BGP completion contract](../product/BGP_COMPLETION.md)
and its leaf contracts describe their boundaries.

## Current follow-up scope

Persisted change and expectation analysis now shares a bounded source-scope
inventory. Change output separates applied native continuity effects from
source boundaries or metadata that produced no route action. The source
occurrence and its witness remain available to the consumer.

`ImportedSourceEvent::new` is a checked construction path for imported
occurrences: it validates bounded source labels and attached source identity
while leaving event-kind, observation-index, and native-effect ownership with
the producer. MRT archive assembly and persisted replay have focused owners in
[`bgp_mrt_archive.rs`](../../product/src/deep/bgp_mrt_archive.rs) and
[`bgp_persisted/replay.rs`](../../product/src/deep/bgp_persisted/replay.rs).

The research path can package a BGP first divergence with the exact source and
range witnesses, and record derived-dataset provenance alongside the comparison
inputs. The bundle remains an unresolved research result pending adjudication;
it does not validate the interpretation by itself. See
[`bgp_compare.py`](../../tools/research/bgp_compare.py) and
[`bundle.py`](../../tools/research/bundle.py).

## Follow-up source-bound validation

The follow-up receipt is
[`pr-followup-validation.json`](../../evidence/pr-followup-validation.json).
It records the source identity, inventory count, product and root gate results,
coherence outcome, bounded sample details, and validation status. Consult the
receipt for its current disposition; this pointer does not assert a pass. The
earlier `8aa92ad` receipt is a historical baseline listed in
[VALIDATION.md](../VALIDATION.md).

## Remaining qualification

The follow-up includes bounded source-bound public UPDATE, chronology, and RIB
prefix samples. Read their exact sizes, completeness, missing parent-source
identity, unsupported entries, and retained coverage gaps from the follow-up
receipt. These samples do not establish complete source coverage or
representative multi-collector, multi-date, or corpus parity.

Normative protocol coverage, sustained fuzzing, complete-byte-copy behavior,
whole-process CPU and physical RSS bounds, and caller-clocked GR/LLGR assessment
remain unqualified. Logical work and retention limits do not establish whole-
process CPU or peak-memory bounds. Actual endpoint state, source authenticity,
route installation, reachability, and causality remain outside the offline
evidence boundary.
