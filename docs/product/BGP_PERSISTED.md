# Persisted BGP query, policy and association

This v1 consumer profile is offline candidate analysis. It accepts sealed captured
journals, MRT stores and BMP stores and replays their raw source records through
their existing bounded verification and canonical reducers. Serialized projection
JSON is rejected. A valid seal establishes byte integrity, never source
identity authenticity, router acceptance, installed routes or reachability.

The CLI emits a create-new file only after full bounded encoding succeeds. Existing
outputs are preserved. A failed attempt may retain an unreachable `.partial`
file for explicit recovery; it never replaces an existing output. Source stores
are read in place and are never copied by this consumer.

## Strict policy profile

The profile is UTF-8, with LF-separated `key=value` lines and an optional final LF.
No blank lines, comments, escapes, carriage returns, leading/trailing value
whitespace, unknown keys or duplicate headers are accepted. Six headers are
required exactly once:

```text
schema=pcap-evidence.bgp.persisted-policy.v1
provenance=explicit-configuration-witness
comparison_context=offline-router-analysis
missing_local_preference=100
med_rule=same_neighbor_as
age_rule=skip
```

`missing_local_preference` accepts a canonical unsigned 32-bit decimal (no leading
zeroes except `0`) or `unknown`. `med_rule` accepts `same_neighbor_as`,
`compare_all`, `skip`, or `unknown`; `age_rule` accepts `same_clock`, `skip`, or
`unknown`. Unknown configuration is absent evidence, never a guessed default.
A missing header is a malformed profile. A present `unknown` rule yields an
unresolved policy result when comparison reaches that dependency. Earlier
conclusive criteria preserve their decisions without consulting later rules.

Zero or more `router_input` lines supply explicitly scoped router-local inputs:

```text
router_input=capture-a|1|192.0.2.1|false|0|192.0.2.1|true|192.0.2.1
```

The eight exact fields are source ID, session ID, peer label, locally-originated
flag, IGP metric, compared router ID, eBGP flag and compared neighbor address.
The three identities select one exact route scope; no wildcard or inferred
address-to-peer mapping occurs. `unknown` in the peer field selects absent peer
evidence. Boolean fields accept `true`, `false`, or `unknown`; the metric accepts
canonical u32 or `unknown`; router ID accepts canonical IPv4 or `unknown`; neighbor
address accepts canonical IPv4/IPv6 or `unknown`. Duplicate source/session/peer
selectors reject. Missing selector rows leave the corresponding policy inputs
unavailable. The provenance header is a caller assertion and does not authenticate
router configuration.

Profiles are capped at 65,536 bytes, further constrained by the caller input and
retained budgets. Values are capped at 4,096 bytes, identities at 1,024 bytes and
router rows at 256 (also constrained by the element budget). Malformed numbers,
addresses, field counts, enum values and profile versions fail closed.

## Query and policy operations

```bash
pcap-depth bgp query STORE --output NEW_FILE --prefix 203.0.113.0/24 --afi 1 --safi 1
pcap-depth bgp policy STORE --policy-profile PROFILE --output NEW_FILE
```

Rich query and policy preserve exact v1 filters `--session`, `--prefix`, `--afi`,
`--safi`, `--peer`, `--source`, `--checkpoint` and `--status`. CIDRs use canonical
network address and length text, with no host bits or textual aliases. No matching
rows produces an explicit empty array. Status accepts `active`, `withdrawn`,
`superseded`, `unresolved`, `rejected`, `stale_graceful`,
`stale_long_lived_graceful`, `stale_at_eor`, and `collector_candidate`. The earlier
session-only query path remains compatible. Default queries and policy calls with
no new selectors keep their v1 schemas and field sets.

The additive selector profile automatically selects the full v2 query/policy
wrapper. `--evidence full` also selects it without extra filters; `--evidence
legacy` conflicts with new selectors. Full state and association are selected
explicitly through `--evidence full`; replay and export retain their existing
store-specific outputs. `Query::default()` remains a v1 query; named
`query_evidence`, `policy_evidence`, `state_evidence` and `associate_evidence`
methods provide explicit full evidence APIs.

| Selector | Accepted value and interpretation |
| --- | --- |
| `--prefix-mode` with `--prefix` | `exact`, `contains`, or `contained-by`; the selected network equals, contains, or is contained by the row network; address families must agree |
| `--asn` with `--asn-role` | Nonzero canonical u32 and `origin` or `path-member`; both are required; the existing validated ASN selector rule is shared with streaming windows |
| `--community` | Canonical u16:u16 pair; set membership |
| `--large-community` | Three canonical u32 components separated by colons; tuple set membership |
| `--extended-community` | Exactly 16 lowercase hexadecimal digits identifying eight raw bytes; membership of an effective raw attribute occurrence, with no interpretation of unknown community semantics |
| `--next-hop` | Canonical IPv4 or IPv6 address; membership in the validated next-hop address set, including a global/link-local IPv6 pair |
| `--partition`, `--generation` | Exact native partition ID and canonical u64 generation |
| `--direction`, `--lifecycle` | Explicit direction `0` or `1`, and canonical captured lifecycle u64 |
| `--path-id` | `absent`, `unknown`, or canonical u32; no implicit ADD-PATH inference |
| `--attribute-scope` | `current-effective` (the default for attribute selectors), `any-retained-version`, or query-only `observation-event` |
| `--version-index`, `--occurrence-id` | Zero-based retained version index and exact source occurrence ID, scoped by each returned route row |

All selectors form a conjunction. Attribute predicates and a reported-time
predicate must match the same validated occurrence of one retained version.
Current-effective matching requires a current native route with exactly one
current version; withdrawn, replaced, superseded, stale or collector attributes
cannot match as current. Any-retained-version mode includes the retained versions
and returns the exact matching version index, attribute identity, disposition and
occurrence reference in `attribute_matches`. Version and occurrence selection does
not alter the reducer's native state or manufacture a semantic identity.

Origin ASN matching requires a complete unambiguous validated path whose terminal
segment is AS_SEQUENCE; a terminal AS_SET, unresolved AS_TRANS, unresolved width or
incomplete semantic identity remains uncertain. Path-member matching checks
ordinary AS_SET/AS_SEQUENCE members using the same existing rule. Confederation
segments are not silently treated as ordinary path members.

A reported label-time window requires all five options:

```text
--reported-clock-policy source-label|ingestion-label
--reported-clock-id EXACT_ID --reported-clock-source EXACT_SOURCE_ID
--reported-start-ns SIGNED_I64 --reported-end-ns SIGNED_I64
```

The interval is `[start,end)` in signed nanoseconds, with `start < end`. A source,
policy or ID mismatch excludes that clock; a missing clock/time remains typed
uncertainty. No timestamp establishes measured accuracy or comparability. A
row-only time query uses the row's reported last observation; an attribute-scoped
time query uses its exact occurrence's clock and time. Observation events,
withdrawals, resets and boundaries belong to the separate `changes` consumer.
`--attribute-scope observation-event` selects exact validated source occurrences,
including rejected announcements and withdrawals, and emits them in the separate
`observation_matches` array with an empty native `routes` array. Each match carries
its exact route key, source occurrence ID, normalized observation digest,
observation/route index and captured lifecycle. A raw extended community can remain
unsupported for admission into a native attribute version while its eight bytes
match a source occurrence. `semantics_unknown` and
`raw_extended_community_semantics=unknown` preserve this limit;
`native_version_claimed=false` prevents promotion into accepted/current state.
Observation-event queries reject native `--status` and `--version-index` selectors.
Policy rejects observation-event scope. Current-effective and retained-version
queries retain missing-version/current-attribute uncertainty for rejected rows.

The v2 `selector_coverage` reports matched, excluded and uncertain row counts,
typed uncertainty counts, up to 64 row witnesses (further bounded by caller
limits), and the omitted-witness count. Missing or unsupported attributes,
clocks, scope fields and native current versions cannot turn into evidence of
absence. A known predicate mismatch excludes its conjunction; an existential
retained-version match resolves uncertain alternative occurrences. Selector
coverage is explicitly labeled `coverage_scope: "selector_fields"` and
`source_coverage: "unknown"`. It describes availability of selector fields in
replayed evidence. Zero uncertain rows never proves complete capture/import
route population coverage or the absence of missing routes.
V1 missing checkpoint/peer filters preserve their previous exclusion behavior;
v2 reports reached missing evidence explicitly.

CLI flags reject duplicates, incomplete selector groups, conflicting scope,
noncanonical integers/addresses/CIDRs, malformed community values and reversed
windows before store I/O. Query and policy output is measured as a complete
encoded aggregate before publication. The exact byte limit accepts the document
(and the CLI newline); one byte less rejects. Existing outputs are never replaced.

Ordinary captured BGP observations populate `observed_at_ns` from the exact
signed 64-bit timestamp of the greatest capture-frame ordinal among all raw
spans contributing to that message. Reconstructed span order and numerical
maximum timestamp do not select the clock. Missing, noncanonical or
unrepresentable time on that selected frame stays unavailable; earlier frames
cannot fill it. This is a capture evidence clock with unknown calibration and
uncertainty, not an endpoint event clock or evidence of cross-source timing.
The emitted `depth_bgp_capture_metadata` projection names that basis and its
availability explicitly.

For a retained TCP `flow.start` session, direction zero labels canonical
endpoint a as `peer` and b as `local`; direction one reverses those IP labels.
These are source/destination evidence labels and do not infer an AS relationship,
BGP neighbor configuration or endpoint negotiation. Missing/invalid flow keys,
missing/unknown direction or bounded retention exhaustion leaves both labels
unavailable and records that unavailability in the emitted depth projection.
Retention uses fixed-size IP address pairs capped by the element budget; flow
end and coverage boundary events retire those pairs before session ID reuse.
The private disk-backed packet map charges 65 bytes per captured frame,
including the timestamp and its availability; source/hash/span checks still
precede metadata use. Existing sealed journals preserve the populated fields
through fresh replay and query without a persisted schema migration.

Each rich route retains the original source kind/ID, partition, session,
generation, direction, peer, family, path ID, checkpoint and clock. Every native
attribute version and its witness list remains available. TABLE_DUMP_V2 entries
remain collector candidates with unresolved direction scope; they are never
promoted into a captured Adj-RIB-In. Imported BGP4MP and BMP use their native
RIB reducer outputs rather than the legacy candidate projection.

Captured and imported native announcement rejections are separate rich rows with
`status=rejected`, `native_current=false`, and no accepted attribute versions.
Their `rejection` object retains the reducer's exact reason and record ID,
the normalized observation SHA-256, and its observation occurrence ID. The
source partition, native route key, checkpoint and clock bind each occurrence
to the sealed raw replay. Other rows carry `rejection=null`. Repeated rejected
occurrences remain distinct; they cannot replace an older accepted route with
the same key or become policy candidates. Policy lists these rows as rejected
exclusions and keeps their occurrence metadata among the alternatives.
Captured rejections retain their original partition and exact lifecycle; their
occurrence ID combines the lifecycle, verified journal-record digest and
normalized observation digest, using the same identity as association. Capture
checkpoint and imported-clock evidence remain absent. END, CLEAR and subsequent
session-label reuse preserve old rejection rows as historical exclusions.

Policy evaluates each exact original partition, direction and prefix separately.
All decisions and alternatives are returned; there is no cross-partition or
cross-source global winner. A capture partition can compare its different peers.
An imported batch/checkpoint partition may include peer/local identity and
therefore yields separate decisions. Cross-partition ranking is unsupported in
this version. Wire attributes supply observed path/origin/MED/local-preference;
configuration supplies router-local inputs. Unknown/ambiguous required inputs
remain unresolved. Age comparisons require explicit comparable clock evidence;
record order is never substituted for elapsed time.

The wrappers are `pcap-evidence.bgp.persisted-query.v1` and
`pcap-evidence.bgp.persisted-policy-result.v1`. Policy results embed typed
`pcap-evidence.bgp.policy-result.v1` objects with the complete deterministic
ordered comparison trace. Their existing `candidate_store_binding` remains
`not_provided_by_policy_api`; the outer persisted wrapper separately binds the
input rows and decisions to the verified source-store receipt and terminal
SHA-256. Neither digest authenticates an external source. Replay relationship
configuration and its explicit/unknown basis are retained in store references.

For a single imported input, `--peer-relationship unknown|internal|external`
configures that replay's relationship-dependent attribute interpretation. Omission
leaves the relationship unknown with `default_unknown` basis; an explicit value,
including `unknown`, has `explicit_configuration` basis. This caller setting
does not infer a relationship from ASN equality, peer labels or source identity.
Captured journals reject this imported replay override.

## Multi-source association

```bash
pcap-depth bgp associate STORE --with-store OTHER_STORE --comparison-namespace explicit-analysis --clock-policy same-clock --output NEW_FILE
pcap-depth bgp associate STORE --with-store OTHER_STORE --comparison-namespace explicit-analysis --clock-policy ignore --clock-basis explicit-spatial-only --output NEW_FILE
pcap-depth bgp associate INTERNAL_STORE --with-store EXTERNAL_STORE --peer-relationship internal --other-peer-relationship external --comparison-namespace explicit-analysis --clock-policy same-clock --output NEW_FILE
```

Association configures each input independently. `--peer-relationship` applies
only to the first `STORE`; `--other-peer-relationship` applies only to
`OTHER_STORE`. Both accept `unknown`, `internal` or `external`. Each omitted
option remains absent (`default_unknown`); the first input's setting never
supplies the second input's context. The ordered `stores` references retain each
setting and basis. Valid LOCAL_PREF evidence remains usable for internal peers,
is discarded from effective attributes for external peers while its source bytes
remain available, and leaves route actions quarantined when the relationship is
unknown. The same scoping applies to MRT and BMP inputs, including mixed pairs.
An override on either captured input rejects. `--other-peer-relationship` is
accepted only by `bgp associate`; single-input operations and imports reject it.
Duplicate options, missing values and unsupported values fail with Usage before
publishing output.

A comparison namespace is a mandatory caller-established mapping. It does not
rewrite either store's original namespace or partition. `same-clock` compares
only the same policy and clock ID at zero label distance, using all reported
uncertainty bounds. Known unequal policies or clock IDs make a pair incompatible
under that policy. Missing time, unknown clock identity or required-but-unknown
uncertainty leaves it unresolved. Captured observations with present time carry
`capture:<capture namespace hex>` source labels with unknown reported uncertainty;
equal labels still do not establish calibrated time. `ignore` requires a nonempty
explicit basis and records that choice. No clock calibration or causal ordering
is inferred.

The output `pcap-evidence.bgp.persisted-association.v1` references each sealed
store by receipt, terminal digest, replay options and original namespace. It
embeds the existing association engine's typed report; route projections use
the explicit v2 side described in [BGP_ASSOCIATION.md](BGP_ASSOCIATION.md).
Native reducer statuses label old/unresolved observations non-current, including
a BGP4MP gap after a malformed record. Source clocks and checkpoint partitions
remain distinct. Equal semantic fingerprints never merge original source
occurrences. All comparisons and alternatives remain visible within the caller
budgets. Trust is unauthenticated and coverage is unknown unless separately
provided by an appropriate evidence owner; this consumer invents neither.

## Proof limits

The focused source-built tests exercise fresh-process replay, policy selection
and reached missing inputs, MED scope, tie breaks, filters, sealed multi-source
association, unknown clocks, exact output limits, no-overwrite, projection denial
and corrupted-source denial. Their execution status belongs to the current
receipt, not this contract text. These tiny synthetic cases establish neither
real-corpus parity, large-scale/RSS performance, source authenticity, endpoint
state, sustained fuzz robustness nor complete normative BGP/BMP qualification.

## Native lifecycle and stage scope

Captured END and CLEAR close a source lifecycle. Their terminal native entries
remain historical with original statuses and `native_current=false`; a close is
not a withdrawal. Reused session labels start a distinct lifecycle. Rich rows
retain `original_partition_id` and expose the lifecycle-qualified comparison
`partition_id` plus `captured_lifecycle`. Current membership joins the exact
normalized observation digest, verified journal record digest, lifecycle and
native generation/path scope, so a reused record label cannot revive old evidence.
Both association sides receive typed announcement/current disposition; inactive
and withdrawn alternatives remain visible but do not count as potential candidates
or cause multiplicity. Adapted source occurrence IDs preserve original record
labels in provenance and keep distinct packet/lifecycle occurrences separate.

Imported policy decisions also retain the full native session, peer and generation
scope. BMP pre-policy and post-policy stages therefore produce separate decisions
without an explicit stage comparison mapping. Captured peers may compare within
the supplied policy context, exact lifecycle partition, direction and route family.
Consumer limits are rechecked after ample source loading: rows and alternatives
are measured by borrowing their attribute subtrees before projection copies, and
aggregate row/group counts and structural limits are admitted before output.
