# DNP3 non-secure workflow slice

## Current DNP3 fragment and streaming confirmation source candidate

Accepted root/streaming base: `d9f7c4fbb80c5355643b241fafb9c7687091a1b5`.
The root API and streaming projection are separately bounded integrations.
Windows native checks are recorded below; Linux and macOS runtime receipts remain
open and are not inferred from Windows results.

### Public seam and report contract

`correlate::dnp3_confirmation_candidates(&[ApplicationAnalysis], &Limits)` returns
`Result<Vec<Dnp3ConfirmationCandidate>>`. The root engine stores the successful
list separately in `Analysis::dnp3_confirmation_candidates`; a typed failure is
stored in `Analysis::dnp3_confirmation_error`, makes `has_diagnostics()` true, and
leaves the new list empty. JSON uses the same two top-level field names. Existing
`transaction_candidates`, transaction statuses/reasons and the ordinary
request/response verifier are unchanged. In particular, its historical CONFIRM
reason `fragment_confirmation_observed_pairing_not_implemented` still refers to
that old transaction path; it does not describe this new, separate report.

A row is one bounded identifier group, not a selected device acknowledgement.
`confirms` and `targets` contain `reference.application` and `reference.fragment`
(zero-based indices into root applications and that application's DNP3 fragments),
`captured_direction`, `source`, `destination`, `link_dir`, `raw_control`, `function`,
`sequence`, `con`, `uns`, `fir`, `fin`, exact `header`, `packets` and
`link_witnesses`. `flow` is the existing caller-established flow index. The source
capture hash additionally separates otherwise identical numeric flow IDs.

`excluded_targets` retains valid colliding identifiers that fail CON/direction
eligibility, with a reason. `unclassified_fragments` contains original
application/fragment references whose identifiers cannot safely be trusted. An
unclassified row has a typed `error` and no invented trusted header fields.
Resolve these references through existing root fragment/link evidence rather than
silently dropping the malformed bytes. The row status/reason is one of:

| Status | Reason and meaning |
|---|---|
| `candidate_confirmation` | `unique_verified_fragment_identifiers_not_receipt_or_causality`: exactly one confirm and eligible target, without conflicting alternatives |
| `unmatched_confirmation` | `no_verified_response_fragment_matches_all_confirmation_fields`: one verified confirm, no eligible target; excluded alternatives remain visible |
| `ambiguous` | `duplicate_or_reused_confirmation_identifier`, `duplicate_or_reused_response_identifier`, or `unverified_fragment_identifier_in_same_flow`; never select a winner |
| `unclassified` | Exact verifier error field/code; original references retained, no verified identifiers invented |

Multiple confirms in one group and their possible targets are alternatives, not
an assertion that every confirm paired with every target. A possible target must
satisfy all matching conditions jointly against at least one verified confirm;
there is no selected edge for an ambiguous group. Target-only groups do not
fabricate confirmation rows; their original response fragments remain visible.

### Eligibility, witness verification and bounds

The key uses source capture, flow, reversed **individual** addresses, fragment
sequence and UNS namespace. Eligibility also requires opposite capture directions
(0/1), opposite observed link DIR, function 0 and CON=0 on the confirm, and function
0x81/UNS=0 or 0x82/UNS=1 with CON=1 on the response fragment. No timestamp, list-order,
nearest-neighbor, port, FCB/FCV-state, message-first-sequence or guessed endpoint
role heuristic chooses a partner. FCV is checked only by the existing link-format
admissibility gate, not used as a correlation key or state machine. Sequence
15-to-0 rollover is not evidence of a new transaction epoch.

`semantics::dnp3_workflow::verified_fragment_witness` reparses each original link
frame and its CRCs, reconstructs contiguous transport bytes with source spans,
checks all derived public link/application metadata, and returns `FragmentWitness`
with exact application and link/transport headers. It is independent of mutable
`ApplicationMessage` membership/completeness. Identical in-assembly transport
duplicates preserve every captured packet dependency without selecting new bytes.
Repeated frame indices and post-FIN frame additions are rejected, not used to
hide duplicate CONFIRMs. Missing middle bytes, conflicting duplicates, truncation,
CRC/length failures and inadmissible addresses cannot authorize a witness.

All DNP3 fragments are verified **before filtering by function** so a forged public
APDU role cannot hide an original duplicate CONFIRM. An unverifiable or unsupported
fragment blocks a unique positive candidate in that same supplied flow, because
assigning its untrusted identifier to just one group could hide a conflict. This
is deliberately conservative: even a supported pair sharing a flow with an opaque
secure-function fragment remains ambiguous. Other flows are not tainted. Link
failures which never produced an application fragment retain their existing root
rejected ranges/issues; missing transport data is not invented as a candidate.

Callers establish capture provenance, flow identity and captured direction before
this seam; link/APDU bytes alone cannot authenticate a packet's origin or network
flow. The verifier checks supplied source-bound evidence for internal consistency,
not authenticity of arbitrary caller-created captures. It does not replay devices,
verify receipt, infer acceptance, decrypt security objects, or decode object data.
A CON-requesting response header with opaque objects can remain a header candidate;
that does not promote its body to decoded or authenticated semantics.

One shared counter across this function call charges application/fragment traversal,
bytes/spans before verification/copy, each matching comparison and copied ambiguous
references against `max_correlation_checks`. `max_protocol_messages` bounds total
examined fragments; `max_application_bytes` bounds each APDU reconstruction.
Counter overflow or exhaustion returns `LimitExceeded`, not a truncated partial
list. This pass and existing transaction correlation each use the same configured
ceiling independently; neither silently consumes or changes the other's results.
Deterministic ordered grouping is presentation order only, never pairing evidence.
Report serialization retains its caller's existing output-byte limit.

### Exact source projection and compatibility

Application headers (two bytes for CONFIRM; four including IIN for responses),
ten-byte CRC-bearing link headers and one-byte transport headers always include
exact hex, length, SHA-256 and packet-relative source spans, even when bulk payload
hex is disabled. Full link-frame length/hash and original DNP frame index accompany
each dependency. All contributing packet IDs include nonselected transport
duplicates. Packet timestamps remain in the existing root packet records; no time
is manufactured, normalized, or used to select a confirmation. The new report
sets `acceptance_established`, `device_effect_established` and
`normative_conformance_certified` to false.

The new Rust public structs are `FragmentRef`, `Dnp3ConfirmationFragment`,
`Dnp3ExcludedConfirmationTarget`, `Dnp3ConfirmationCandidate`, `FragmentWitness`
and `FragmentLinkWitness`. The two new `Analysis` fields require updates to
exhaustive external Rust struct literals. No stable ABI claim is made. Existing
JSON consumers must tolerate additive sections. No new CLI option is required:
ordinary root `analyze` reports contain this section, and `--require-clean` sees a
new-pass typed error through existing diagnostics. The streaming crate now adds
an independent TCP-only `dnp3.confirmation_candidate` projection. It is scoped
by capture/session/window/generation and exact verified participant evidence;
generic transaction events remain unchanged. UDP datagrams never pair across
datagrams, and product-depth/history consumers do not consume this event yet.

### Validation and next smallest slice

`tests/dnp3_confirmations.rs` authors 38 native cases, including fixed solicited/
unsolicited candidates, unmatched/conflicting/reused identifiers, multiple
outstations, fragment-level sequence rollover, incomplete-message targets, public
metadata/provenance mutations, all truncation prefixes, transport duplicate/gap/
conflict cases, explicit budgets, JSON witnesses/timestamps and a real-CLI test.
Authored test cases are not evidence of execution by themselves. The text fixtures contain
33 independently constructed links plus an eight-packet PCAP encoded as hex.
Executed independent Python arithmetic checks verify CRCs, hashes, packet lengths,
checksums, 15 header-relation cases and exact expected source offsets. They do not
execute Rust grouping, the witness verifier, root JSON or the CLI.

The exact patched worktree has passed the required Windows native gates. Format,
build, focused/all-target tests and warnings-denied Clippy are now locally green;
the streaming projection additionally has focused unit, contract and semantic
pipeline coverage. Fresh Linux and macOS runtime receipts remain open. The root
decoder now also has a separately bounded Group 70 free-format file-object slice:
variations 3--8 retain exact metadata/transport spans and hash filename,
file-specification, authentication-key, and content bytes. Next, extend DNP3 only
as separately bounded slices; do not expand this result into deep cross-APDU
completion, late-state inference, or secure semantics.
Live/platform, scale, fuzz, real-corpus and normative gates remain open.

### Root-object shape regression coverage

The root semantic object decoder is shared by direct semantic decoding and the
workflow projection. The tests below exercise that shared decoder directly;
the framing/reassembly layer is not a second semantic implementation. Current
focused regression coverage in `tests/semantic_subset.rs` proves these byte
shapes and alignment properties:

| Object | Required shape |
| --- | --- |
| Group 4 variations 1/2/3 | Two-bit double-bit state; 1/7/3 octets including time where present; distinguish all four encodings while retaining the raw flags octet |
| Groups 21/22/23 variations 5/6 | 11/9 octets including the trailing 6-octet timestamp; preserve timestamps and following-object alignment |
| Group 40 variation 4 | 9-octet record: status/flags plus IEEE-754 binary64; preserve bit patterns and following-record alignment |
| Group 41 variation 4 | 9-octet record: 8-octet IEEE-754 binary64 value followed by command status; preserve bit patterns and following-record alignment |
| Group 70 variations 3/4/5/6/7 | Fixed-field extents 26/13/8/9/20 octets; every fixed-field read, subtraction, slice and emitted span must remain inside that child’s declared length even when sibling bytes follow. Variation 7’s filename tail is separately bounded by its declared child length. |

Coverage is provided by `dnp_group4_event_variations_decode_all_double_bit_states_and_align_sibling`,
`dnp_counter_event_variations5_and6_decode_timestamps_with_exact_boundaries`,
`dnp_group40_and_41_variation4_decode_float64_and_keep_sibling_alignment`,
and the four `dnp_group70_*children*`/`dnp_group70_*fixed_child*` tests. These
include truncated and adjacent-child vectors. Reject undersized children
without panic, cross-child reads, or fields whose source spans escape the child. The
public [DNP Users Group validation bulletin](https://www.dnp.org/Portals/0/Public%20Documents/DNP3%20AN2013-004b%20Validation%20of%20Incoming%20DNP3%20Data.pdf)
is a useful primary implementation reference for these object widths; it is a
technical bulletin, not a claim that this bounded slice implements or is
certified against the complete/current IEEE 1815 standard.

## Inherited workflow baseline

The following describes the preceding integrated workflow slice, originally based
on `fcbfddbf5565b25e46d9849aef39698c47713bbc`. Its Windows acceptance predates
the confirmation-candidate changes and is historical baseline evidence, not a
fresh result for those changes.

## Scope and evidence authority

This change extends, rather than replaces, the reviewed root object decoder.
Its one/two/four-byte ranges, indexed READ selectors, non-secure fixed layouts,
deadband, variable-octet identity, CROB, and assembled-message pass are retained.
No dependency, device simulator, transmission, credential extraction, or secure
payload decryption is added. Interpretations concern captured bytes only.

The new source-bound link observer separates PRM and DIR from FCB/FCV or the
secondary reserved bit/DFC. It exposes the existing function names and applies a
narrow admissibility check: primary 0/2/3/4/9, secondary 0/1/11/15, matching FCV and
user-data presence, ordinary source addresses, and explicit destination classes.
Legacy or unreviewed functions are unsupported, not silently reclassified.
Reserved combinations are rejected. An FCB bit with FCV clear is retained but
not used as endpoint state or as the deduplication criterion.

Addresses 0xFFF0--0xFFFB are reserved, 0xFFFC is an unresolved self address, and
0xFFFD/0xFFFE/0xFFFF encode broadcast application-confirm policies of not-required,
required, and optional respectively. Those names describe address encoding, not
observed receipt or confirmation. Broadcasts never enter unicast pairing. Multiple
ordinary address pairs stay separate; their presence is not proof of a physical
multidrop bus or of how many devices exist.

## Application workflows

A complete, source-bound APDU exposes raw control/function, FIR/FIN/CON/UNS,
sequence, and raw IIN where applicable. Header consistency is checked before
workflow interpretation. Non-secure coverage is deliberately bounded:

| Workflow | Captured evidence exposed | Not established |
|---|---|---|
| CONFIRM (0) | Exact two-byte header and namespace; additive root fragment candidates above | Application acceptance, receipt or causality |
| READ (1) | Existing root headers and indexed selectors; class and event-family header labels | Returned event counts, requested-versus-returned object coverage, device configuration |
| WRITE (2) | Group 50 variation 1 or 3, qualifier 0x07, count one per header; existing raw 48-bit time layout | Clock correction, time synchronization, record/write causality |
| SELECT/OPERATE/DIRECT OPERATE (3--6) | Existing CROB subset, unchanged | Successful control or physical effect |
| ENABLE/DISABLE UNSOLICITED (20/21) | One or more Group 60 variations 2--4 with qualifier 0x06; selectors only | Configuration changed or an event subscription established |
| DELAY MEASURE (23), RECORD CURRENT TIME (24) | Exactly two-byte, FIR+FIN requests; ordinary candidate response pairing | Derived RTT, clock offset, or a record-current-time/write transaction chain |
| FILE CONTROL (25--28, 30) | Group 70 free-format qualifier 0x5B variations 3--8; exact length-prefixed object spans, bounded command/status/transport/descriptor metadata, hash-only filename/file-specification/authentication-key/status-text/content evidence, and opt-in bounded cross-APDU candidate reconciliation keyed by session/endpoints/handle | File authentication (29), authentication variation 2, endpoint-authoritative transfer/session completion, credentials, raw sensitive bytes, or endpoint file effect |
| RESPONSE (0x81), UNSOLICITED RESPONSE (0x82) | Header, raw IIN and existing non-secure root object layouts | Endpoint state, event-buffer state, authenticated identity |

Group 60 READ selection was already supported; this patch does not claim it as a
new layout. ENABLE/DISABLE contexts add no values to those selectors. Group 50
uses existing value widths rather than a second time parser. Zero counts,
unsupported qualifier forms, empty class-control/time-write bodies, truncation,
and neighboring unsupported layouts have explicit negative tests.

Functions outside the rows above retain their names but are outside workflow
decoding. Secure-authentication functions/objects and file authentication remain
opaque or unsupported. Root Group 70 free-format qualifier 0x5B now supports bounded
file-object variations 3--8: command metadata, command status, transport content
hashes, transport status, descriptor metadata, and specification hashes are
source-bound to exact object spans. Variation 2 authentication objects remain
explicitly opaque. The opt-in depth sink correlates complete assembled Group 70
messages into conservative candidate evidence with explicit gaps, duplicate or
conflicting blocks, and source witnesses; it does not establish endpoint success
or file effect. Group 0 supports a
bounded generic attribute envelope: typed scalar widths, known boolean
variations, hash-only string/octet/bit values, and even-length list entries;
unknown/private semantics remain opaque and secure attributes remain non-secret
evidence only. The legacy opt-in deep file subset remains separate and is not
promoted to root or normative support by this slice.

## Correlation

Root and streaming pairing first reconstruct the authority for each complete
message from its original CRC-checked link frames. Address, primary user-data
function, DIR, transport sequence/flags, raw APDU bytes, source spans, application
function, control/sequence, object slice, and packet witnesses must agree with
public mutable metadata. Verification work is bounded across the query.

Within one supplied flow/session scope, pairing still means **candidate identifiers,
not causality**. A solicited response function 0x81 and a known non-secure request
must have reversed individual DNP addresses, consistent master/outstation DIR,
opposite capture directions, and the same initial application sequence. Reused
identifiers are ambiguous; sequence 15 to 0 is not a license to assign a new
transaction epoch. No timestamp window or greedy ordering heuristic is introduced.
Missing partners remain unanswered/orphan observations. Confirm and unsolicited
messages do not enter this request/response namespace. Functions 6/8/10/12 do not
create expected-response hints. Streaming UDP pairing remains disabled.

## Reconstruction and incomplete evidence

The root transport assembly keeps at most 64 sequence slots per active addressed
assembly. Identical in-assembly duplicates retain their link/packet witnesses but
do not contribute another selected byte value. A previously seen identical segment
outside the next contiguous slot is explicitly a reordered duplicate. Conflicting
non-FIR duplicates invalidate the pending assembly; later orphan continuations
cannot fill it by majority vote. A contiguous 63-to-0 rollover replaces its slot.
Repeated FIR starts and completed-message sequence reuse remain conservative
boundaries/ambiguity, not inferred retransmission epochs.

A CRC-valid header supplies an exact declared link extent. A bad payload CRC cannot
cause scanning for another frame inside that extent. A truncated declared extent
retains all available bytes and the declared length. An invalid recognized header
has no trusted end, so the rest of that chunk is retained and not rescanned.
`rejected_link_ranges` records these raw byte ranges and identities. A following
frame at an independently declared boundary can still be observed with the failure
reported; this is not repair of the rejected frame.

Root complete application-message assembly remains the authority for cross-APDU
object completion. Incomplete messages and non-single APDU fragment projections no
longer decode their object regions as if they were standalone complete objects.
Missing fragment sequence positions are explicit, but their absent byte lengths
are unknowable from these captures and are not invented.

Deep continuation now uses the root workflow decoder for standard complete APDUs,
keeps original link-frame evidence alongside APDU/header/object evidence, retains
identical immediate duplicate witnesses, and exposes link-only observations.
Every DNP feed failure poisons the parser until an explicit `cut`; cut/finish
retains pending evidence. Reordered/conflicting transport evidence is rejected and
cut rather than repaired. Multiple application fragments receive explicit
incomplete reports: **deep cross-APDU assembly is not implemented here**. The legacy
`ApplicationSequence` helper also refuses partial-fragment object decoding.

There is no new categorical late-after-completion classifier. Orphan/cut and reused
identifier evidence is retained rather than guessing whether a packet is late,
new, or a retransmission. Finalized TCP-history conflict adjudication remains an
upstream precondition of deep continuation.

## Public API and output compatibility

The new `pcap_evidence::semantics::dnp3_workflow` module provides:

- `link(&EvidenceBytes, semantics::Limits)` and `application(...)`: bounded
  source-bound `Report` values for a complete link frame or complete APDU;
- `header(&EvidenceBytes)`: byte-derived header checks, not endpoint authorization;
- `address_kind`, `is_broadcast`, `broadcast_confirm_policy`, and `link_issue`;
- `verified_message_direction(&Dnp3Result, &ApplicationMessage, &Limits, &mut usize)`:
  bounded witness verification; the returned bool is DIR, not acceptance/success.

`semantics::dnp3::Context` gains `TimeWriteValues` and `ClassHeaders`.
`assembled_message_json(objects, function, complete, limits)` preserves incomplete
status. The existing `message_json` is kept and requires a caller-established
complete assembled body; it does not verify an arbitrary caller's `complete` claim.
The link/workflow decoder likewise does not establish flow identity on its own.

`Dnp3Result` gains `rejected_link_ranges: Vec<RejectedLinkRange>`. Rust callers using
exhaustive struct literals or exhaustive `Context` matches must update; no stable
ABI compatibility claim is made for these public Rust type additions.

Snapshot reports gain `link_workflow`, `application_workflow`, address-policy
fields, and exact rejected-link evidence. Streaming gains separately labeled link
messages (including link-only traffic), `object_semantic_subset` for the assembled
body, and orphan fragment observations. Keep the existing per-fragment array;
consumers must now honor its incomplete status. Extra link/issue events consume
existing event budgets and change event counts; filter `data.layer` instead of
assuming every DNP message event is an application message. Rejected/unsupported
link-control observations must not be rendered as decoded application candidates.

Deep reports carry nested `root_application_workflow`, `application_evidence`,
`link_frame_evidence`, and the existing upstream header witness. The record range
of a nested workflow is local to that APDU, not to the outer object-body buffer.
Original packet IDs and offsets resolve through existing capture/run packet and
timestamp records; no timestamp is created, normalized, or used for pairing.
Raw evidence/hash identity survives even when semantics stop. Hashes establish
integrity, not truth or origin authentication.

## CLI entry points

No new flags, ports, live modes, or network access are introduced. After native
validation, existing offline commands expose the additive fields:

```sh
cargo run --locked --offline -- analyze CAPTURE -o NEW_ANALYSIS.json
cargo run --manifest-path streaming/Cargo.toml --locked --offline -- analyze CAPTURE --run-id local-run --output NEW_EVENTS.ndjson
cargo run --manifest-path product/Cargo.toml --locked --offline --bin pcap-depth -- analyze CAPTURE --workspace NEW_DEPTH_DIRECTORY --format ndjson
```

Use fresh output paths and preserve source capture/run identity. These examples
are invocation documentation, not a receipt that any command ran.

## Evidence and next slice

Fixed wire vectors are in `tests/fixtures/dnp3_workflows.hex`; its companion JSON
records independently calculated CRC/length/hash expectations. Preserve these
fixtures and assertions. Each code change requires fresh native qualification;
do not reuse historical results as current receipts. See
`product/VALIDATION.md` for the validation plan and latest recorded results.

The fragment-confirmation addition above, bounded Group 0 attributes, bounded
Group 70 free-format file-object projection, and a conservative opt-in
cross-APDU file-transfer candidate reconciler are integrated and Windows-qualified.
Root-to-streaming projection is also integrated. The next separate implementation
slice is full endpoint-authoritative transfer semantics or secure semantics;
endpoint state and normative conformance remain separate.

The CRC reference uses polynomial 0x3D65 in MSB-first orientation with reflected
input/output and xor-out 0xFFFF; `123456789` yields 0xEA82. Fixed expected bytes are
not generated at Rust test runtime by the parser being tested. Public Step Function
function-code documentation and its link header/layer source were comparison
inputs only (header blob `b055f47eab51ebf594b76a2bfb309be5ef78df16`, layer blob
`77c474235bf2ae139b77e842c66c7ddbf756c69f`). No reference implementation was copied or
made a runtime dependency/correctness oracle. IEEE 1815 edition-level adjudication
has not been performed and no normative conformance is claimed.
