# Current implementation pointer

This page points to the active offline BGP surfaces, the merged implementation
baseline, and the next qualification work. It is navigation, not proof by itself.

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

## Merged implementation baseline

[PR #1](https://github.com/btothefifth/rust-pcap-analyzer/pull/1) merged into
`main` at `1d41a6d6ce91983dcba28f7e7cb85b4584d1b650`. Its tree is identical to
the reviewed `b23e911` revision; the receipt below remains bound to that source
generation.

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

## Merged baseline validation

The follow-up receipt is
[`pr-followup-validation.json`](../../evidence/pr-followup-validation.json).
It records the source identity, inventory count, product and root gate results,
coherence outcome, bounded sample details, and validation status. Consult the
receipt for its current disposition; this pointer does not assert a pass. The
earlier `8aa92ad` receipt is a historical baseline listed in
[VALIDATION.md](../VALIDATION.md).

## Active follow-on: bounded BGP corpus and semantic comparison

The follow-on branch starts with the scope and acceptance criteria in
[the BGP qualification plan](../product/FOLLOWUP_QUALIFICATION.md#bounded-bgp-corpus-and-semantic-comparison).
Its target is broader source diversity and independently produced comparable
route fields, using the existing replay, per-field export, comparator and bundle
owners. The implementation is rebased onto cleanup PR #3 at
`fabca5c961c09c9d14ba0cbf7df35a045965e278`. Eight parser/replay repairs, Telnet
selectivity and the bounded comparison recipe are implemented. The
[PR #2 receipt](../../evidence/pr2-corpus-validation.json) records eight public
samples and independent synthetic witnesses, with missing OPEN and IPv6 RIB
coverage explicit. One plan review and two implementation review rounds are
complete; the final implementation round found no actionable findings. All 56
product gates and 16 root gates passed on the unchanged reviewed source. Final
status/receipt updates record those results separately. Hosted CI and merge are
external follow-up gates; the earlier merged receipt remains historical.

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

## Cleanup audit

The [cleanup audit](CLEANUP_AUDIT_2026-11-09.md) records the repository review,
regression repairs, validation scope, and remaining evidence limits.
