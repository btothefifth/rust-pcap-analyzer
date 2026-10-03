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

Rich query and policy share exact filters `--session`, `--prefix`, `--afi`,
`--safi`, `--peer`, `--source`, `--checkpoint` and `--status`. CIDRs use canonical
address and length text. No matching rows produces an explicit empty array.
A missing checkpoint/peer does not match a requested value. Status accepts
`active`, `withdrawn`, `superseded`, `unresolved`, `rejected`, `stale_graceful`,
`stale_long_lived_graceful`, `stale_at_eor`, and `collector_candidate`. The earlier
session-only query path remains compatible. Replay, state and export retain
their existing store-specific outputs.

Each rich route retains the original source kind/ID, partition, session,
generation, direction, peer, family, path ID, checkpoint and clock. Every native
attribute version and its witness list remains available. TABLE_DUMP_V2 entries
remain collector candidates with unresolved direction scope; they are never
promoted into a captured Adj-RIB-In. Imported BGP4MP and BMP use their native
RIB reducer outputs rather than the legacy candidate projection.

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

## Multi-source association

```bash
pcap-depth bgp associate STORE --with-store OTHER_STORE --comparison-namespace explicit-analysis --clock-policy same-clock --output NEW_FILE
pcap-depth bgp associate STORE --with-store OTHER_STORE --comparison-namespace explicit-analysis --clock-policy ignore --clock-basis explicit-spatial-only --output NEW_FILE
```

A comparison namespace is a mandatory caller-established mapping. It does not
rewrite either store's original namespace or partition. `same-clock` compares
only the same policy and clock ID at zero label distance, using all reported
uncertainty bounds. Missing/unknown/incompatible clocks or uncertainty yield an
unresolved result. `ignore` requires a nonempty explicit basis and records that
choice. No clock calibration or causal ordering is inferred.

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
