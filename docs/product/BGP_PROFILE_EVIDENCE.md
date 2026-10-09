# Bounded BGP profile evidence

This is the Objective 4 synthetic proof inventory for generation O14-1, based
on `b66e624f17e02975d5b74e0cd4e8c305a65bd4b4`. The controlling contracts are
[BGP completion](BGP_COMPLETION.md) and
[Objectives 1–4](../implementation/OBJECTIVES_1_4.md). The support matrix remains
the feature-status owner. This inventory selects actual consumers and independent
expectations; a selector below is a proof obligation until its receipt is run
on the applicable final source. It does not certify every value combination
within a broad matrix row.

Primary sources checked for the new valid controls on 2026-10-03:
[RFC 4271 sections 4.1–4.3](https://www.rfc-editor.org/rfc/rfc4271.html#section-4.1)
define the common header and OPEN/UPDATE fields;
[RFC 6793 sections 3 and 4.1](https://www.rfc-editor.org/rfc/rfc6793.html#section-4.1)
define the four-byte ASN capability value and bilateral four-byte AS_PATH
layout. [RFC 7606](https://www.rfc-editor.org/rfc/rfc7606.html) is the existing
attribute-disposition authority. This check supports the specific controls;
it is not complete normative review of every profile row.

## Charter and consumer inventory

The owned seam is hand-built bytes/events -> public decoder/session/RIB/policy
and sealed journal -> independently asserted terminal evidence. Valid routes,
new-generation progress, an early policy winner, and a verified replay must
remain possible. Truncated bytes, wrong ownership, historical resurrection,
invented policy authority, partial output, journal alteration and overwrite
must be suppressed at their owning boundaries. Cancellation/concurrent workers,
network peering and endpoint timers are not present in this synchronous offline
campaign; other lanes own CLI/BMP/import integration. Representative corpus,
performance, resource-scale and normative review remain unexecuted dimensions.

For each Rust selector, use `cargo test --manifest-path product/Cargo.toml
--locked --test TARGET SYMBOL -- --exact`. Python vectors use
`python3 product/tests/FILE.py`; they independently derive byte extents and
expected meanings and are not claims about Rust execution. Existing tests below
were inspected for their consumer and asserted behavior; their existence is
neither current validation nor complete profile qualification.

| Matrix row | Supported consumer and selected proof | Independent expectation and unproved/out-of-profile boundary |
| --- | --- | --- |
| S001 core | `CapturedSessionPipeline::apply_message`; `bgp_profile_properties::bounded_wire_scope_and_truncation_preserve_valid_state`; direct `bgp_phase1::stateless_framer_preserves_coalesced_add_path_and_extended_message_boundaries` | RFC 4271 header/OPEN/UPDATE arithmetic, existing producer Python vectors. New campaign covers one valid OPEN/UPDATE layout and every nonempty UPDATE truncation; NOTIFICATION/KEEPALIVE/ROUTE-REFRESH need their existing owning vectors. Full endpoint FSM is not exercised. |
| S002 capabilities | `decode_pcap` -> `SessionState`; `bgp_phase1::declared_capability_occurrences_keep_exact_ranges_and_unknown_hash`, `add_path_requires_bilateral_directional_capability_evidence`, `extended_message_authority_is_the_receivers_advertisement` | Python `bgp_phase1_vectors.py` code/length, directional ADD-PATH and extended-message arithmetic. Declared capability codes have typed occurrences; unknown values stay opaque. This campaign establishes bilateral ASN width only. Value-dependent negotiated endpoint truth and every extended OPEN boundary are unqualified. |
| S003 NLRI | `decode_pcap` -> candidate path key; `bgp_phase1::mp_nlri_without_bilateral_family_capability_stays_opaque`; `bgp_profile_properties::bounded_rib_source_path_generation_and_failure_are_isolated` | Prefix/path-ID/scoped-event model; independent Python ADD-PATH layout. Direct RIB path identifiers are exercised; that is not wire ADD-PATH coverage. Specialized AFI/SAFI grammar remains opaque; real MP/ADD-PATH captures are absent. |
| S004 core attributes | direct UPDATE occurrence/disposition -> atomic captured pipeline; `bgp_phase1::rfc7606_dispositions_control_emitted_route_actions`; `bgp_pipeline::treat_as_withdraw_reaches_rib_as_withdrawal_not_rejection` | RFC 7606 disposition rules plus independent attribute flag/length vectors. Campaign valid ORIGIN/AS_PATH/NEXT_HOP controls have no peer-dependent attributes. Flags, duplicate/malformed attributes and peer-context matrix require their owning tests; broad malformed recovery and endpoint action remain unqualified. |
| S005 common extensions | `decode_pcap` typed occurrences; `bgp_phase1::declared_extension_attributes_keep_typed_values_and_malformed_dispositions` | Python extension tuple widths/OTC boundary. Wire occurrence support is distinct from specialized policy semantics; campaign does not generate extension attributes. Unknown neighbors remain raw evidence; normative coverage per extension remains open. |
| S006 AS semantics | `decode_pcap` reconstruction -> normalized identities; `bgp_phase1::old_new_as4_suffix_and_aggregator_are_reconstructed_from_raw_occurrences`, `longer_as4_path_and_new_new_context_do_not_replace_the_base_path` | Python independent AS4 counting/aggregator arithmetic and RFC-derived hand-built NEW/OLD vectors. Campaign valid four-octet AS_SEQUENCE is only a grammar control. AS0/confederation/discard and complete identity rules require the semantic lane's selectors; endpoint use is unqualified. |
| S007 refresh/restart | session/RIB/pipeline boundary APIs; `bgp_phase1::enhanced_route_refresh_markers_require_bilateral_layout_context`; `bgp_session_rib_policy::gap_stale_eor_and_refresh_are_explicit_observations` | Explicit-event transition model and Python EOR/reset wire neighbors. Campaign reset is caller-observed transport evidence; no graceful/LLGR expiry is inferred. Automatic stale derivation and complete enhanced-refresh operations remain unproved. |
| S008 route state | public `AdjRibIn::apply`, pipeline -> entries; `bgp_profile_properties::bounded_rib_source_path_generation_and_failure_are_isolated`; `bgp_import::replay_before_a_reset_does_not_resurrect_retired_routes` | Independent terminal-set model: withdrawal touches one path, reset closes source A, B survives, exact old replay is inert, new A can progress. Store replay checks those same capture consumers. Imported BGP4MP/BMP state and identity quarantine belong to other lanes; new property alone does not qualify them. |
| S009 policy | `bgp_policy::evaluate` -> canonical writer; `bgp_profile_properties::bounded_policy_preserves_early_winner_unknown_and_atomic_output`; `bgp_session_rib_policy::policy_missing_med_rule_is_unresolved_when_med_is_reached` | Explicit caller policy and independent first-criterion expectation: greater local preference wins; absent reached preference cannot win; permutation preserves full trace. Exact encoded-size admission and one-byte-below suppression are exercised. MED/age/tie and persisted policy remain owning-suite obligations; no router installed-state claim. |
| S010 external input | `MrtBatch::parse` -> normalized import/replay; `bgp_mrt::identical_route_bytes_from_distinct_collectors_keep_distinct_partitions`, `unknown_types_families_and_attribute_semantics_remain_source_bound` | Independent MRT header/peer/RIB/BGP4MP arithmetic in `bgp_mrt_vectors.py`. Same hashes do not authenticate collectors. New captured journal campaign is not MRT/BMP adapter coverage; other lanes provide their bounded primary-spec vectors, malformed/corrupt and state consumers. |
| S011 integration | `JournalWriter` -> fresh `bgp_store::replay` -> canonical RIB entries; `bgp_profile_properties::bounded_sealed_source_replays_and_tamper_is_rejected`; ordinary `pcap_depth_cli::bgp_pcap_depth_emits_normalized_route_evidence` | Direct pipeline entries must equal fresh reduction from sealed source records. Same valid source passes before altered first-record digest fails; no-overwrite preserves original bytes. Library reconstruction does not by itself prove a new OS process; the existing CLI selector owns that boundary. Policy/import/BMP product commands require integrated receipts. |
| S012 qualification | `bgp_profile_properties` six exact tests and `bgp_bounded_campaign` native example | Deterministic bounded synthetic properties plus one terminal authority assertion mutant. No coverage-guided runtime, fuzz dependencies or nightly graph is installed. Sustained fuzz, lawful real corpus, scale/RSS/throughput, security/normative review and exact-head platform receipts remain distinct, unqualified gates. |

## Native campaign and limits

`product/tests/support/bgp_profile_campaign.rs` is the single shared generator
and property owner. The example and test harness call the same public APIs.
Every iteration completes all four families with accepted controls and adverse
attempts. The seeded LCG varies prefix octet, path identifier and local
preference; it does not imply random exploration of the full protocol profile.
UPDATE truncation retains its complete declared length, matching source scope
and packet provenance. Ownership inverses assert the intended guard's field.
The independent state expectation is defined before candidate reduction; the
policy expectation uses the first explicit ranking input rather than a second
copy of the candidate evaluator. Journal identity is verified before a digest
alteration, preserving container framing and provenance reachability.

Example invocation (ordinary pinned stable toolchain and root-owned target):

```sh
cargo run --manifest-path product/Cargo.toml --locked --example bgp_bounded_campaign -- 730 1000 32768 1048576 60 /tmp
```

The first native attempt (six selected tests) produced one pass and five
fixture/oracle failures: a 4 KiB input limit also capped normalized report JSON
and rejected the valid control before wire/store assertions; an early policy
winner retains all ten trace slots, marking later criteria skipped, rather
than truncating the trace to one slot. The corrected harness uses a 32 KiB
input/report cap and independently asserts the first decisive step plus nine
skipped steps. The authority mutant in the failed attempt stopped at the trace
assertion and supplies no mutation-sensitivity evidence. Production limits
and policy behavior were preserved; the canonical one-byte output refusal
remains unchanged.

Arguments are seed, maximum completed iterations, per-input byte cap, retained
byte cap per public consumer, elapsed-time admission cap in seconds, and scratch
parent. Accepted ranges are 1–10,000 iterations, 32–64 KiB input, 128 KiB–4 MiB
retention, and 1–60 seconds. Work is capped at 2 MiB per consumer, output at the
selected retention cap, active sessions at four and elements at 128. The time
cap is checked between iterations; it does not interrupt a synchronous consumer
mid-call. The printed completed count is authoritative if time expires early.
The process retains one source journal and one altered witness with a combined
cap below 64 KiB; each iteration removes both. Scratch ownership is one unique
directory; cleanup removes only these two known files and that empty directory.
No growing corpus, crash archive, repeated log, repository copy or capture
download is produced. Consumer byte limits are distinct from allocator RSS.

The normal selectors include valid output, exact canonical output size and
one-byte-below refusal without destination mutation. The controlled authority
mutant starts with the actual successful policy result, changes its terminal
endpoint flag, then invokes the same assertion used for ordinary outputs;
`#[should_panic]` confirms the oracle distinguishes that harmful result. It is
an assertion-sensitivity witness, not a production fault-injection coverage
claim or proof of a repaired parser bug.

## Execution receipts

Generation 2 focused execution on 2026-10-03 used Rust
`1.85.1 (4eb161250 2025-03-15)` and Cargo
`1.85.1 (d73d2caf9 2024-12-31)` on the Linux host. The six
`bgp_profile_properties` tests passed, with zero failures or ignored tests,
in 0.28 seconds after a 14.84-second compile. The controlled authority mutant
passed its expected-panic selector, so its intended terminal oracle was reached.
The receipt is `.local-build/native-semantic-controls.log`; unrelated semantic
checks in that diagnostic batch did not all pass, and this owning result does
not promote that batch to integration acceptance. Root classified the initial
fixture failures as corrected; independent source and correction review found
no material findings and verified the frozen before/after hashes.

The root built the native example, then the qualification lane ran only that
immutable executable (no Cargo invocation) with:

```sh
.local-build/target/debug/examples/bgp_bounded_campaign 73055078868883 1000 32768 1048576 60 /tmp
```

The process exited 0 and reported:

```text
seed=73055078868883 requested=1000 completed=982
wire_negative_cases=47136 disk_peak_bytes=1740 elapsed_ms=60050
input_cap=32768 retained_cap=1048576 time_cap_seconds=60
sustained_fuzz=false corpus=false scale=false normative_qualified=false
```

Every counted iteration completed the valid and adverse controls in all four
families. The 60-second check occurs between iterations; the final synchronous
iteration accounts for the 50 ms overrun. `disk_peak_bytes` is the maximum
combined logical file length of the original and altered journals, not allocated
filesystem blocks or RSS. The separate allocation sampler raced with successful
cleanup before publishing its peak: **physical allocation peak is NOT
ESTABLISHED**. No repeat was performed solely to recover that supplemental
measurement. Preflight measured 980,635,648 allocated bytes for the checkout and
its in-tree project artifacts, with 10,014,347,264 bytes available on `/tmp`.
The campaign's two journals have a declared combined cap below 64 KiB.
The exact scratch directory `/tmp/bgp-profile-206657-73055078868883` was removed;
there were no matching seed scratch directories before or after the run.
The stdout receipt is one bounded line; no corpus or growing campaign log was
retained.

These raw-byte identities matched before and after execution:

| Input or executable | SHA-256 |
| --- | --- |
| `product/tests/support/bgp_profile_campaign.rs` | `f5e50d98671841b0eb27912e2e6eeb294b2d22c8d4b81d73a2841f1fe2fa9b1d` |
| `product/tests/bgp_profile_properties.rs` | `eb50fbd19e0d6fe0c899683a2aef4eac89ebdf2c56a40f4dbf24ada95643908a` |
| `product/examples/bgp_bounded_campaign.rs` | `2dd80da90da3c377caba5bec0c8206246f7c7659b88352b05d7f8578bb30587b` |
| Evidence document at execution, before this receipt was appended | `34e5143af026f9a979a814e224106535fd17ec4dcc0a74c19d795e231fba655c` |
| `.local-build/target/debug/examples/bgp_bounded_campaign` (7,901,304 bytes) | `1edd8e8cf1245e57d13de3e876d9ff0cfd598db30d5d4d2717fc4f6a5459dc0a` |

This is a finite synthetic receipt bound to that executable and the accepted
campaign source generation. Later parser, semantic, or persisted-consumer edits
must not relabel it as proof of a newly built final executable. The root owns
applicability of this composable receipt, final assembled-source property tests,
independent integration review, and exact published-head platform CI. Sustained
coverage-guided fuzzing, lawful real-corpus disagreement adjudication, measured
scale/RSS/throughput, security and complete normative profile review remain
unqualified.
