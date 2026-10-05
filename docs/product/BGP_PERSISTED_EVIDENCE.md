# Additive persisted evidence profile

The sealed capture/MRT/BMP consumer retains immutable native observations and
route versions. The legacy `query`, `policy` and `associate` outputs keep their
existing key sets and schema names. `state_evidence`/`query_evidence` use
`pcap-evidence.bgp.persisted-query.v2`; `policy_evidence` uses
`pcap-evidence.bgp.persisted-policy-result.v2`; `associate_evidence` uses
`pcap-evidence.bgp.persisted-association.v2` around the new
`pcap-evidence.bgp.association.v3` report. New typed query selectors select the
full profile automatically; the CLI owns explicit full/legacy selection.

A full route row adds `version_occurrences`. Each accepted version retains all
exact matching occurrence references alongside the original version, attributes,
attribute identity, witness record labels, and native disposition. References
carry schema, record label, exact source occurrence ID, normalized observation
digest, route index, full source/native route scope, lifecycle, sealed journal
ordinal and byte bounds where available, original namespace, checkpoint,
clock/time, the validated semantic identity, original normalized observation,
and provenance. Captured packet evidence and imported source-relative ranges
remain separate coordinate systems. Original imported range order and repetitions
are preserved. A record label alone cannot resolve a version witness. Native
scope, generation, lifecycle, full route key, attribute identity, and exact
attributes must all match. An authoritative native occurrence stamp additionally
binds the actual version merged/appended by the reducer to the original validated
observation digest and route/action index, under its native event index. The full
version carrier names its exact `native_version_index` and `origin_binding`;
missing origins stay explicitly unavailable. Bound references use
`route-occurrence-reference.v2` with `native_origin`. Raw observation-event refs
and collector candidates retain v1 refs and no native admission claim. Native
identical replay with a new normalized source digest adds evidence to the original
version without changing currency; immutable event/digest replay remains inert.
No association between versions is recovered from labels, equal attributes or
guessed observation order. Historical/replaced/withdrawn versions remain evidence.

Read-only `retained_route_versions`, `source_route_occurrences`, `observations`,
`captured_observation_evidence`, `captured_source_events`, and
`imported_source_events` expose the typed retained frontier. The internal
`observation_partition` helper owns canonical captured lifecycle partitions for
route-free and route observations alike. Selector occurrences
borrow routes by immutable observation and route indices; consumers do not
reconstruct semantic identities from JSON. Raw observation-event matches may
include rejected announcements and withdrawals, but cannot become policy inputs.

Policy converts only a historical `Active` row lacking native current membership
to `Unresolved`. Withdrawn, superseded, graceful/LLGR stale, stale-at-EOR, rejected,
and already-unresolved statuses retain their native exclusion reason. Matching
an old retained version does not promote it or change policy's current inputs.

The full association report adds a typed `semantic_relation` to each association:
`equal`, `distinct`, or `unavailable`. Equality/distinctness require two validated
complete identities of the same identity schema and compare their canonical
payloads. Missing, incomplete, opaque, or mixed-schema identities are unavailable.
A semantic result does not change prefix/time compatibility, native current
membership, partition identity, occurrence retention, or any authority flag.

Full association source notes retain both inputs' source/store bindings and typed
metadata/boundaries. `note_plane=normalized_observation` retains the canonical
route-free observation; `note_plane=source_container_event` retains the original
verified archive event plus typed scope/context and continuity cuts. A bound
observation index joins those planes where supplied. Their note multiplicity is
not a source-event, change-event, or route occurrence count. Typed archive events
retain source record order independently of canonical report-note order. OPEN,
EOR, gap, reset, rejection, END, and CLEAR notes do not invent routes or withdrawals.

Captured time, when actually present, uses an explicit source label
`capture:<capture namespace hex>` with unknown reported uncertainty. This is a
capture-evidence clock label, not calibrated time. Absent capture time retains an
unknown clock. Imported observations keep their producer-owned clock metadata.

The runtime admits aggregate occurrence/reference and note bytes, elements,
fields/depth, provenance spans, retained storage, work, and final output before
publishing. Full projections borrow and measure evidence subtrees before copying
them. The new exact-output regression admits the measured complete encoding and
rejects one byte below it. Typed source archive carriers also charge prospective
scope/cut/reference storage before their new copies. Prospective source-note measurement includes every repeated
receipt, final wrapper depth, typed context, continuity cut and provenance range
before witness construction. Captured snapshot and persisted copy admission
includes the newly retained native origin vectors. Exact aggregate fields/depth/spans controls cover
multiple notes. BMP Route Monitoring containers are session metadata; their bound
normalized observations alone carry the verified BGP message kind.

Migration owners are `bgp_persisted.rs` for wrappers and route projections,
`bgp_association.rs` for report fields and semantic relation,
`bgp_store.rs` and the imported source stores for typed source event retention,
`bgp-association-evidence.schema.json` for v3 exact report key sets, the existing
`bgp-association.schema.json` for unchanged v1/v2 reports, and
`bgp-route-occurrence-reference.schema.json` for explicit v1/v2 occurrence and native-origin exact key sets, and `bgp_persisted_evidence_schema_vectors.py` for old/new key/version cross-product
rejection. `bgp_persisted_evidence.rs` owns finite sealed-replay status, occurrence,
semantic-relation, route-free/boundary, imported-range and output-budget witnesses.
The query child and CLI own selector specification, selector uncertainty,
per-version conjunction matching and explicit full/legacy dispatch.

## Captured decoded continuity evidence

A successfully decoded captured UPDATE with opaque NLRI can create a native
Gap even when its normalized observation has no route action to display. The
captured source-event carries `CapturedSourceEvent.continuity` as an optional
`CapturedDecodedContinuity` containing the verified observation index,
observation digest and native `DecodedContinuity` decision. Its original journal
ordinal, record digest, byte extent, capture lifecycle, metadata and packet
mappings remain attached. The versioned event adds `decoded_continuity` only for
a typed decision; events without one retain the exact v1 shape. See
[BGP_CAPTURED_CONTINUITY.md](BGP_CAPTURED_CONTINUITY.md) and
[bgp-captured-source-event-v2.schema.json](bgp-captured-source-event-v2.schema.json).
The effect is integrity/provenance evidence, not source authentication, and its
scope comes from the native reducer rather than a route key, peer label,
reported direction alone, or output JSON.

`changes` and `expectations` process the event at its original source ordinal
before applying route, attribute, time, or other output filters. Changes clears
only predecessors in the native affected scope; it does not synthesize a
withdrawal. Expectations retains an applicable newly applied continuity effect
as uncertainty for an absence-dependent result under caller-declared coverage.
A cached replay may retain the original witness but cannot reapply the boundary.
Valid empty non-EOR UPDATEs and explicit EOR alone do not create a decoded Gap
or Reset. The rules for Gap, identity collision, peer-binding mismatch, and
predecessor Reset scopes are owned by the native reducer contract in
[BGP_SESSION_RIB_POLICY.md](BGP_SESSION_RIB_POLICY.md).

These results are offline evidence. They do not authenticate sources, establish
endpoint negotiation, installation, reachability or causality, collapse source
partitions, select a preferred external source, or certify full protocol coverage.

The occurrence reference schema validates structural closure only. Native event, version and route ordinals are zero-based; the producer digest equals the normalized observation digest. The public full state/query/policy carriers retain these v2 references with complete output admission. Association consumes the same verified version bindings when establishing eligibility; its named report schema remains association.v3. Raw observation-event and collector references remain v1. The sealed-replay owning test validates actual emitted v1 and v2 references against the schema and checks exact/one-below full query output size after native origins are included.

Embedded RIB admission uses `for_embedded_projection`: it validates the original public limits, keeps retention/work/elements and other caps, and bounds the native logical output proxy by the smaller of caller retention and the default native output ceiling. Public captured normalized receipt and BMP final archive output still use the caller's actual encoded-byte cap. Owning controls admit those public outputs at their exact size and reject one below; captured refusal preserves decoder, observer, native events/entries and receipt replay behavior, while BMP replay leaves the sealed source bytes unchanged. Standalone RIB output-unit admission is unchanged.
