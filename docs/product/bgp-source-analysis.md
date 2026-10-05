# Generic offline source changes and caller expectations

`pcap-depth bgp changes STORE --output NEW_FILE` emits the source record occurrences retained by
verified native replay, including announcements, explicit withdrawals, OPEN and
control observations, EOR when its typed family evidence is available, gaps,
resets, rejected containers, end-session and clear events. The output keeps exact
capture lifecycle or import checkpoint partition, record coordinates and evidence
references. It orders source records and their occurrences; reported timestamps
do not reorder them. Checkpoints remain independent native partitions.

Repeated announcements remain distinct. Before/after compares the entire
validated attribute identity only when both observations have complete supported
attribute evidence. The output labels unchanged repeats, complete changes and
unresolved differences. A newly applied native gap, reset or session end breaks the applicable
comparison segment. Captured decoded boundaries carry their original source
ordinal, validated observation identity and owning native affected scope. Native
quarantine can cover a whole session generation even when its reporting witness
has a direction. Imported containers likewise carry the effect actually admitted
by the native reducer, including its affected previous generation for Reset.
Their original reporting context, record occurrence and source-range witnesses
remain unchanged. Imported change events expose this inventory in
`native_continuity`, alongside typed `source_id` and `checkpoint_id`; the original
`reference`, `import_context` and `continuity_cuts` remain evidence of the source
occurrence. The inventory contains newly admitted effects only; its generation
fields are independent of the occurrence's original reporting generation. An empty native-effect inventory does not clear predecessor
state or become an all-scope boundary. Metadata with unavailable session context
still has its exact verified source and checkpoint identity; an explicit known
source or checkpoint mismatch excludes it. Immutable replay remains a distinct source occurrence and does
not reapply an old continuity barrier. Valid empty UPDATEs and explicit EOR do
not create a gap by themselves. It never invents withdrawals. Filters reuse the typed query
prefix, ASN-role, standard/large/extended community, next-hop and scoped reported
clock/window selectors. Native predecessor state and boundaries are processed before output filtering. Control boundaries relevant to a selected native scope
remain visible even with route or time filters, because they delimit the scope's
continuity. Terminal-row `status`, `version_index`, `occurrence_id` and
`current_effective`/`observation_event` attribute scope selectors are rejected for this occurrence
command; an explicit `any_retained_version` scope is compatible.

`pcap-depth bgp expectations STORE --profile PATH --output NEW_FILE` evaluates a separate caller
profile. Its meaning is existence of at least one matching announced occurrence
in the exact specified native scope. A later withdrawal does not erase the
historical announcement witness. `supported`, `contradicted` and `unresolved`
refer to this offline observation claim. They establish no installed route,
reachability, source authentication or caller authorization.

The profile is bounded UTF-8 LF `key=value` text. No comments, blank lines,
whitespace normalization are accepted. Version 1 accepts no escapes; version 2
uses the native-text representation described below. Each required header occurs
exactly once; unknown keys and duplicate expectation IDs are rejected. Integers
are canonical unsigned decimal, IPs/CIDRs canonical, and ASN zero is rejected.

```text
schema=pcap-evidence.bgp.expectation-profile.v1
provenance=explicit-caller-description
time_basis=source_occurrence_order
coverage=unknown
expectation=ID|present/absent|SOURCE|PARTITION|SESSION|GENERATION|DIRECTION|PEER|CHECKPOINT|LIFECYCLE|AFI|SAFI|PREFIX|PATH_ID|ASN|COMMUNITY|LARGE_COMMUNITY|EXTENDED_COMMUNITY|NEXT_HOP
```

The nineteen fields are:

1. A unique bounded ID.
2. `present` or `absent`.
3. Exact source ID.
4. Exact native partition ID from the verified query output; captured IDs include `:captured-lifecycle:N` matching field ten.
5. Exact session label.
6. Exact generation.
7. Exact `0`, `1`, or `absent` direction.
8. Exact peer label or `absent`.
9. Exact imported checkpoint ID, or `absent` for capture.
10. Exact capture lifecycle integer, or `absent` for import.
11. Nonzero AFI.
12. Nonzero SAFI.
13. Canonical exact prefix CIDR.
14. Exact ADD-PATH integer or `absent`.
15. `origin:N`, `path_member:N`, or `unknown` for no ASN predicate.
16. Standard community as canonical u32, or `unknown` for no predicate.
17. Large community `A:B:C` with canonical u32 values, or `unknown`.
18. Exact eight-byte extended community as sixteen lowercase hex digits, or `unknown`.
19. Canonical next-hop IP, or `unknown`.

Native `absent` tokens match absence exactly; they never mean any peer, direction,
checkpoint, path or lifecycle. Exactly one of capture lifecycle and import
checkpoint must be present. Attribute `unknown` means the caller supplied no
predicate for that attribute.

Version 1 remains accepted with its original syntax and meaning. Its bare
`absent` token cannot represent the literal checkpoint or peer label `absent`.
Use `schema=pcap-evidence.bgp.expectation-profile.v2` for that identity. Version 2
changes native text fields three (source), five (session), eight (peer) and nine (checkpoint):

- `none` means exact native absence in optional peer/checkpoint fields only.
  Required source/session fields must use `text:VALUE`.
- `text:VALUE` means an exact present native label. `VALUE` uses literal ASCII
  letters, digits, `-`, `.`, `_`, and `~`. Every other UTF-8 byte must be encoded
  as `%HH` with uppercase hexadecimal digits. Escaping an unreserved byte is
  rejected, so each label has one canonical representation.
- `text:absent` and `text:none` preserve those literal labels. A label `a|b%`
  is `text:a%7Cb%25`; `text:` in a label is encoded as `text:text%3A`.

Decoded labels must be nonempty after trimming, control-free UTF-8 and at most
1024 bytes, matching the existing imported metadata owner. Their bytes remain
exact, including encoded whitespace or Unicode. Encoded native text fields may
occupy up to 3077 bytes; aggregate profile/input/allocation limits are unchanged.
All other fields retain the version 1 grammar, including `absent` for missing
numeric direction, lifecycle and path ID. Header order is unchanged: schema may
appear before or after expectation rows. The result records the input
`profile_schema` and the SHA-256 of the original profile bytes. Existing sealed
source labels and raw-source store versions are unchanged; fresh replay builds
the typed source and native-effect metadata from the checked source owner.
Regular typed source/session/peer/checkpoint query selectors compare the decoded native label.

A matching announcement directly supports `present` and contradicts `absent`;
all repeated exact witnesses remain retained. Unknown/opaque selector evidence
is retained independently even if another selector excludes the route. Changes
output also retains this independent field availability, including unavailable
reported clock/time or unsupported prefix relations, in `selector_coverage`;
its `coverage_scope=selector_fields` and `source_coverage=unknown` do not claim
a complete route population. Missing
matches under `coverage=unknown` remain unresolved. The alternative
`coverage=caller_declared_complete` can produce an absence-dependent result
only when the exact scope has observations and no relevant incomplete, opaque or
boundary evidence. Such a result explicitly says it is conditional on the caller
declaration. The output continues to report `verified_source_coverage=unknown`.
An empty sealed store does not prove absence. Native cuts and rejected containers
never become inferred withdrawals or complete observation coverage. A captured
boundary whose generation was unavailable remains uncertainty for its exact
known session and lifecycle when a later generation becomes observable.

Existing default limits remain unchanged. Profile bytes and parse allocation,
source/witness counts, typed event metadata, borrowed evidence size, aggregate
span references and aggregate output are admitted before large evidence clones or serialization. Profile file reads admit the input byte length and parse allocation before
reading. Exact output
byte/span admission and one-unit-below rejection are covered by the finite synthetic
test matrix. Local tests and source review are separate evidence gates; neither
establishes normative conformance, representative corpus parity or platform
qualification.
