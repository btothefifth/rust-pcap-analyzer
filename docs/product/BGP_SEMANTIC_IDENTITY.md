# Cross-source BGP semantic identity

Status: controlling implementation leaf for BGP-C08 semantic comparison. This
defines a parser-evidence identity only; it is not a route-authority contract.

## Responsibility

Define when a captured BGP UPDATE and an imported MRT route can be described as
the same normalized route semantics while preserving their independent source
evidence and state partitions. This leaf refines [BGP completion](BGP_COMPLETION.md)
and is owned by the capture/MRT normalizers and the shared route-evidence model.

## Intent contract

- A semantic match means only that the supported, validated route fields
  represented by both parsers normalize equally.
- Capture offsets, packet ordinals, MRT record indexes, timestamps, source IDs,
  checkpoints, source kind, attribute wire order, and encoding-only length form
  are provenance or wire evidence, not semantic identity.
- The semantic identity includes NLRI family, prefix, and every supported
  route-affecting attribute. ADD-PATH Path Identifier is deliberately excluded
  from cross-source semantic identity because it is locally assigned and has
  no semantics outside its source/session; it remains in source-scoped route
  state keys, so distinct paths are not merged by the reducer.
- Only announcements can receive a complete fingerprint. Withdrawals and
  other route actions are evidence events, not route-semantic candidates.
- Unknown, unsupported, malformed, unresolved-context, or otherwise
  incomplete route semantics cannot receive a **complete semantic fingerprint**. Keep any
  exact-byte digest in a separately labeled opaque-evidence field; byte equality
  is not semantic equality.
- A match may link evidence records, but it must never merge source partitions,
  deduplicate source events, establish contemporaneity, or claim peer
  acceptance, route installation, propagation, or reachability.
- Original per-occurrence evidence is retained independently of the normalized
  identity. Normalization must not erase or rewrite source-byte provenance.

## Versioned representation

The compatible additive representation is
`pcap-evidence.bgp.semantic-route-identity.v1` with these logical fields:

| Field | Rule |
| --- | --- |
| `schema` | Exact version above. |
| `completeness` | `complete`, `incomplete`, or `unresolved`; never infer `complete` from a successful outer parse alone. |
| `fingerprint_sha256` | Present only for `complete`; hash the canonical semantic payload with a domain separator and explicit length framing. |
| `opaque_occurrence_fingerprints` | Optional, per-occurrence hashes for unsupported values; labeled byte-evidence only and excluded from the semantic fingerprint. |
| `incompleteness_reasons` | Deterministically sorted codes naming unknown, unsupported, malformed, duplicate, or unresolved-context causes. |
| `canonical_payload` | Optional bounded diagnostic projection. It contains normalized route key and supported semantic values, never source identity or wire offsets. |

The canonical payload uses a fixed schema and field order. Scalar values use
their protocol-domain numeric/string representations. Sets are sorted and
deduplicated only where the applicable standard defines set semantics:
COMMUNITIES and LARGE_COMMUNITY values are sets, and members within AS_SET and
AS_CONFED_SET are unordered. Segment order, AS_SEQUENCE order, and ordered
next-hop data retain their meaningful order. The extended-length encoding bit
and encoded length width are omitted only after validating the attribute
envelope and value. RFC 4271's reserved low flag bits are ignored semantically
but retained in occurrence evidence. A malformed flag combination or Partial
attribute value on an effective occurrence prevents a complete identity. A
later ordinary duplicate discarded under RFC 7606 does not change the effective
identity even if its own flags or value are malformed; retain that occurrence
and its disposition as separate evidence.

For Large Communities (RFC 8092), semantic values are an unordered set: sort
and deduplicate the 12-octet tuples for the semantic payload while retaining
every original occurrence and its exact bytes separately. Standard
Communities (RFC 1997) are also set-valued. Do not generalize these rules to
another attribute without an explicit standards basis. A field named
`value_sha256` hashes only the attribute value bytes, not the attribute TLV.

## Producer-to-consumer procedure

1. **Capture producer:** retain each attribute occurrence, exact byte range,
   flags, validation/disposition, decoded projection, and source packet
   evidence. Build a semantic candidate only from values the UPDATE parser has
   positively classified as understood, valid, and unambiguous.
2. **MRT producer:** parse each supported TABLE_DUMP_V2/BGP4MP attribute with
   the same value normalizer used by capture. Keep the original MRT record and
   attribute bytes/ranges as separate source evidence. An unsupported RIB
   entry is emitted as `opaque_only` evidence with a null semantic fingerprint
   and is not admitted as a route candidate; supported but Partial attributes
   may retain a normalized projection but remain incomplete and untrusted.
3. **Identity:** canonicalize the route key and supported semantics using this
   versioned contract. Exclude all source/provenance/time/wire-encoding fields.
   If any route-affecting input is unresolved, omit the complete fingerprint.
4. **Correlation:** compare only complete fingerprints. Return a source-bound
   match/link with both evidence references. Do not mutate either RIB, merge
   partitions, or treat the match as proof that the records describe one
   occurrence.
5. **Projection:** publish the identity schema/version and completeness next to
   the evidence references. Preserve the existing false authority flags.

## Required decision table and falsifiers

| Input comparison | Semantic result |
| --- | --- |
| Same valid supported route; different packet/record offsets, source IDs, timestamps, or provenance | Same complete fingerprint; evidence references remain distinct. |
| Same valid supported values in a different legal attribute order or legal short/extended length encoding | Same complete fingerprint; raw occurrence evidence remains different. |
| Any supported route key or meaningful attribute value changes | Different complete fingerprint. |
| Same prefix and supported attributes but different ADD-PATH Path Identifier | Same semantic fingerprint; retain separate source-scoped candidate keys. |
| Large Community tuples or Standard Communities are reordered or repeated | Same complete fingerprint after set canonicalization; all occurrences remain evidenced. |
| A Large Community tuple changes or its encoded length is malformed | Different complete fingerprint, or no complete fingerprint for malformed input. |
| A later ordinary duplicate attribute is discarded under RFC 7606 | First occurrence is the only semantic candidate, subject to its own validation; preserve all occurrences and dispositions, even if a discarded later occurrence has invalid flags. |
| MP_REACH_NLRI or MP_UNREACH_NLRI is duplicated | Session-reset disposition; no complete route identity from that UPDATE. |
| A route-affecting attribute carries the Partial bit | Incomplete identity; do not fingerprint its possibly partial projection. |
| Unknown/unsupported attribute is present | No complete semantic fingerprint. Exact same opaque bytes may be reported as opaque-byte equality only. |
| A required parser context is unknown, conflicting, or directionally unresolved | Unresolved/incomplete; no semantic match. |
| Prefix family or prefix differs | Different route identity even when path attributes match. |
| The route action is not an announcement | No complete semantic fingerprint. |

Tests must exercise both producers and the actual normalized evidence boundary.
Each negative row must fail closed; a fixture rejected by an earlier guard is
not evidence for the intended downstream behavior.

## Required regression tests

- `captured_and_mrt_supported_attributes_share_source_neutral_identity`:
  equal valid semantics despite independent source IDs, record offsets,
  timestamps, packet spans, legal attribute ordering, and legal length form;
  evidence/provenance and reducer partitions still differ.
- `semantic_identity_changes_for_route_key_or_supported_attribute`: vary
  family/SAFI, prefix, next hop, ORIGIN, effective AS_PATH, LOCAL_PREF,
  MED scope/value, and another supported value one at a time.
- `add_path_identifier_is_a_state_key_not_cross_source_semantics`: the
  fingerprint ignores Path Identifier while normalized source-scoped state
  still keys routes by it.
- `large_communities_are_semantic_set_but_occurrences_are_preserved`: reorder,
  duplicate, change a tuple, and truncate the value across both decoders.
- `duplicate_attributes_follow_rfc7606_dispositions`: later ordinary
  occurrences are discarded after the first, including their effect on
  semantic identity; duplicate MP_REACH/MP_UNREACH triggers session reset,
  with every occurrence retained as wire evidence.
- `unknown_attributes_are_opaque_not_semantic`: exact and changed unknown
  transitive type/value/flags; exact bytes can match only in the opaque field.
- `cross_source_match_does_not_merge_partitions_or_claim_authority`: compare a
  capture and MRT record with equal semantics and assert both records, their
  provenance, source partitions, and false authority flags remain intact.

Use RFC 4271 for UPDATE attribute ordering/encoding rules, RFC 7606 for error
and duplicate dispositions, and RFC 8092 for Large Community set semantics.
These primary specifications—not agreement with another dissector—adjudicate
the expected result.

## Promotion criteria and current limitations

Capture and TABLE_DUMP_V2 now emit the same versioned identity for the locally
tested supported subset; the replay also exposes unsupported RIB entries as
opaque-only evidence without admitting candidates. This is a local
implementation slice, not full BGP-C08 qualification: complete profile
coverage, cross-source join/query/export, BGP4MP semantic parity, executable
coverage of every row, exact-commit cross-platform CI, fuzzing, real-corpus
parity, and scale remain separate gates. A normalized complete identity is
validated against its schema, route key, domain-framed payload digest, and the
corresponding normalized route attributes by the state consumer. AS_PATH set
members and Communities are compared using their defined set semantics;
segment/sequence order and CLUSTER_LIST order are preserved. For captured data,
the normalized route projection is also checked against the first effective
captured attribute occurrences, including decoded AS_PATH interpretations and
MP_REACH/MP_UNREACH prefixes. A complete identity cannot carry opaque occurrence
fingerprints. Large Communities are checked against the first effective type-32
occurrence retained in captured attribute evidence. For TABLE_DUMP_V2, the MRT
normalizer retains a separate sorted/deduplicated Large Communities projection
in the route attribute envelope, and the consumer requires it to agree with
the identity payload. The consumer does not independently re-decode the
original source bytes; this consistency check is not source authentication.

The generic `ImportedRouteObservation` adapter deliberately does not emit this
identity. Its typed input does not retain a validated occurrence inventory for
all route-affecting attributes, so it cannot prove the complete supported
projection required for a cross-source fingerprint. External route-collector
ingestion needs a richer adapter contract that preserves supported values,
unsupported/opaque occurrences, and source completeness before it can claim
semantic parity. Its current prefix/time evidence remains available to the
separate association workflow and does not imply semantic equality.

## Direct links

- [Current implementation pointer](../implementation/CURRENT.md)
- [BGP completion contract](BGP_COMPLETION.md)
- Capture normalizer: `product/src/deep/bgp.rs` and `product/src/deep/bgp/producer.rs`
- MRT normalizer: `product/src/deep/bgp_mrt.rs` and `product/src/deep/bgp/mrt.rs`
