# Bounded BMP file adapter v1

This contract covers original file bytes containing concatenated BMP v3 messages,
bounded container framing, reported Peer Up context, Route Monitoring candidates,
and sealed fresh replay. The adapter does not open a BMP socket or act as a BGP
speaker. It is an offline evidence adapter under
[BGP completion](BGP_COMPLETION.md), criterion BGP-C08 and Package D of the
[repository review](../implementation/REPOSITORY_REVIEW_2026-10-02.md).

The primary layout authority is [RFC 7854 sections 4–5](https://www.rfc-editor.org/rfc/rfc7854.html).
[RFC 8671](https://www.rfc-editor.org/rfc/rfc8671.html) defines the O flag for
outbound streams; [RFC 9069](https://www.rfc-editor.org/rfc/rfc9069.html)
defines the distinct Local-RIB peer type.
[RFC 9736](https://www.rfc-editor.org/rfc/rfc9736.html) separates Peer Up
and Initiation TLV namespaces. Codepoints were checked against the
[IANA BMP registries](https://www.iana.org/assignments/bmp-parameters/)
on 2026-10-03. These references establish syntax and reported meanings;
they do not authenticate a supplied file or establish the actual router state.

## Versioned producer and consumer seams

`deep::bgp_bmp` owns BMP framing (`pcap-evidence.bgp.bmp-container.v1`).
`deep::bgp::bmp` supplies BMP-specific reported context to the existing shared
OPEN parser, UPDATE parser, attribute semantics, AS4 reconstruction, and route
envelope. It has no parallel BGP decoder. `deep::bgp_bmp_store` owns immutable
raw-source publication (`pcap-evidence.bgp.bmp-source-store.v1`) and fresh
replay (`pcap-evidence.bgp.bmp-replay.v1`). Every normalized route passes through
the ordinary `Observation::from_normalized` consumer and one
`CandidateState::apply_batch` transaction. Source-neutral imported observation
conversion feeds the ordinary `AdjRibIn` reducer; its replacement, withdrawal,
generation, gap, and history rules remain canonical.

The shared candidate journal preserves source-bound normalized observations.
The `bmp_rib` projection owns the scoped active, unresolved, superseded,
withdrawn, and rejected route statuses. A generic candidate journal entry does
not independently prove uninterrupted BMP monitoring coverage.

Normalized journal publication and native RIB initialization are separate facts.
A complete UPDATE containing only an unsupported family remains normalized
journal evidence, including its exact source bytes and later generation
boundaries, without inventing a native route or EOR marker. A native reset is
forwarded only after that exact source partition/session has admitted a native
event. Supported EOR and Gap events establish that scope even without routes.
Once established, every reset retains the canonical reducer's explicit
predecessor and exact-successor validation. The adapter looks up this fact in
the existing admitted event inventory, charging comparison bytes to the work
cap before inspecting source/session identity; it keeps no duplicate scope map.

## Framing, exact bytes, and supported records

The common header is six bytes: version, big-endian total message length, and
message type. Only version 3 is accepted. Every declared length includes the
common header and must be at least six, fit the source, and satisfy the record
cap. Invalid common framing, unsupported versions, trailing partial headers,
overflow, empty input, and resource exhaustion reject the entire batch.
No accepted prefix is published as a completed import.

The 42-byte per-peer header retains peer type, every flag bit, the eight-byte
peer distinguisher, address, four-byte ASN, BGP identifier, seconds, and
microseconds. IPv4 addresses retain the required zero padding; global peers
require a zero distinguisher. Base peer types 0, 1, and 2 are supported. V is
the address layout, L selects pre/post-policy Route Monitoring, and A selects
the embedded AS_PATH width. O selects an outbound Route Monitoring stream;
that semantic profile is retained opaque in this version. Remaining bits
remain exact evidence and have no invented meaning. Local-RIB peer type 3
uses another flag interpretation and cannot enter the base peer decoder.

| Message | Version 1 behavior |
| --- | --- |
| 0 Route Monitoring | Exactly one framed BGP UPDATE after a supported per-peer header; shared BGP normalization under explicit reported context. |
| 1 Statistics Report | Original bounded record retained opaque; no counter interpretation. |
| 2 Peer Down | Reasons 1/3 require one exact NOTIFICATION, reason 2 exactly two FSM-event bytes, reasons 4/5 no data. Other reasons, including RFC 9069 reason 6, remain opaque. |
| 3 Peer Up | Local address and ports, exact sent and received OPEN ranges, then bounded Peer Up TLVs; shared OPEN semantics. |
| 4 Initiation | Bounded Initiation TLVs with sysDescr and sysName; reported metadata. |
| 5 Termination | Bounded Termination TLVs; closes the observed monitoring generation. |
| 6 Route Mirroring | Original bounded record retained opaque; no claim of lossless mirrored history. |
| Unknown/experimental type | Entire trusted-length record retained opaque; parsing continues at its declared end. |

A malformed known message with complete trustworthy common framing becomes
`malformed_known_record` opaque quarantine. Its exact original bytes, record
range, digest, type, and any safely parsed peer remain available. Unknown
message types have no assumed per-peer layout. Unknown TLVs preserve code,
original value range, order, repeats, and digest without interpreted semantics.
Peer Up string TLVs use its own types 0, 3, and 4; Initiation uses 0, 1, and 2.
UTF-8 strings and ASCII sysDescr/sysName follow their declared namespaces;
VRF/Table Name is 1–255 bytes. Termination requires a Reason TLV with exactly
two bytes. Reasons 0–4 have base semantics; unknown codes remain opaque,
mark monitor coverage uncertain, and gap/block older OPEN-dependent context
until a fresh valid Peer Up, without asserting a valid reset or endpoint down,
and contradictory repeated reasons quarantine the record. Identical repeated
reason codes are unambiguous. Missing Reason, invalid reason length, or other
malformed termination data marks monitor coverage uncertain and gaps tracked
contexts; it does not manufacture a valid termination or session reset.

`BmpBatch::bytes` retains the original input exactly once. Records and TLVs
reference half-open source-relative ranges. The full batch, complete BMP
records, and embedded OPEN/UPDATE/NOTIFICATION occurrences have separate
SHA-256 bindings. These are source ranges, never fabricated packet spans.

## Identity, clocks, continuity, and route effects

The immutable import partition binds caller-assigned source/checkpoint labels,
the complete source hash and length, and the versioned BMP source schema.
The peer key includes peer type, distinguisher, address, ASN, and BGP identifier.
Equal addresses in separate VRFs, equal routes from different sources, and
pre/post-policy streams cannot collapse. A flag changes wire interpretation
only where its normative scope applies; the A flag does not create a peer or
a session generation. The session labels `bmp:N:pre` and `bmp:N:post` identify
source-local peers in first-occurrence order and separate L streams.

Raw seconds and microseconds always remain evidence. Both zero means that the
source time is unavailable. Microseconds outside 0–999999 quarantine semantic
use. Nonzero valid source clocks use `bmp-reported-per-peer-timestamp` with
unknown accuracy. Clocks never reorder records, select peers, or establish
freshness. A timestamp regression therefore preserves file-order route effects.

Peer Up reports one sent OPEN (direction 1) and one received OPEN (direction 0).
These establish a reported grammar hypothesis, with peer ASN/BGP-ID consistency
checks, and never assert endpoint negotiation. Missing, malformed, ambiguous,
or required unresolved advertisements quarantine dependent UPDATE use.
ADD-PATH, multiprotocol, and extended-message interpretation uses the shared
reported OPEN context. The A flag independently sets UPDATE AS_PATH wire width;
BMP may reformat AS_PATH even when reported OPENs lack four-octet capability.
The explicit optional peer relationship applies to all sessions in one replay;
default `unknown` is not guessed from ASN, address, port, or policy stream.

Route Monitoring is a state-compressed view reported by a router, not a
verbatim endpoint UPDATE history. Valid announcements, withdrawals, EOR,
RFC error dispositions, and route identity reuse shared semantics. L=0 and
L=1 effects stay in separate candidate scopes. The adapter does not fabricate
initial completeness, graceful-restart timers, route installation, reachability,
or router configuration.

A valid Peer Down closes all observed L streams of only its peer and advances
that peer's generation. Reason 5 means monitoring coverage was removed and
does not assert that the BGP session went down. A valid new Peer Up establishes
a new reported generation when prior context or routes existed. Termination
closes monitoring contexts; ordinary EOF is not an invented Peer Down.
Repeated Initiation metadata does not reset existing peers. Generation
boundaries preserve route history and do not manufacture per-prefix wire
withdrawal occurrences.

A malformed context-changing record with a safe peer identity gaps only that
peer's old route continuity and blocks reuse of its OPEN context. A valid later
Peer Up resumes it through a new typed generation. If peer identity itself is
unavailable, the adapter reports source-monitor coverage uncertainty, gaps
the tracked candidate scopes, and blocks their old contexts without asserting
that all BGP sessions reset. Each valid later Peer Up can restore its own
reported decoder context; the earlier source coverage uncertainty remains in
the evidence history. Unknown records, opaque stats/mirroring, unsupported
outbound streams, and unsupported Local-RIB peers do not mutate base contexts.
The known Termination type is the narrow exception: an unsupported reason still
prevents its old monitoring context from proving subsequent route continuity.

The source-neutral imported route carrier uses `message_type = 0`; the original
embedded UPDATE remains wire type 2 in its bound source bytes. Shared MRT/BMP
producer helpers compute semantic v2 identity before clearing packet-relative
route spans, then attach the same imported occurrence inventory with complete
raw message prefix/suffix, declared attribute values, message length/digest,
and atomic-aggregate projection. The consumer validates that closure using
original source-relative context. Valid captured/BMP semantics may compare equal
while their evidence partitions stay separate; unsupported attribute semantics
retain an incomplete identity without a usable fingerprint.

## Bounds, publication, and replay

Default framing bounds are 8 MiB input, 1 MiB per record, 4096 records, 256 peers,
4096 TLVs, 16 MiB retained charge, and 32 MiB each for work and typed output
charge. The input hard maximum is 64 MiB. A framing charge counts source bytes,
record/range/peer/TLV representations, hashing traversals, and bounded element
work. It is deterministic logical admission, not allocator/RSS or CPU-time
qualification. Shared semantic `Limits` independently enforce active sessions,
attributes, route fanout, observation/event count, work, retention, and output.
The final replay retention charge sums the source batch (including labels and
batch hash), every retained BMP event, CandidateState journal and cached
snapshot, canonical RIB, and receipt exactly once. Intermediate admission
checks do not replace this combined check. It runs before destination creation
and during fresh replay; `retained_charge` exposes the deterministic final sum.
Replay work also charges exact archive output traversal before publication.

The sealed source store uses magic `PCBBMP01`, little-endian version 1,
length-prefixed source/checkpoint labels, source length/hash, original bytes,
and a domain-separated terminal digest. Parsing and full normalization/reduction
finish before `create_new`; a semantic or resource rejection creates no store.
The writer never overwrites a destination. I/O failure can leave its
caller-owned incomplete path; consumers refuse incomplete/unsealed stores.
File reading admits one regular-file metadata size, reserves fallibly, reads
exactly that size, and probes one byte for growth. Same-size concurrent rewrite
authenticity is outside this byte-identity contract.

Fresh replay validates magic/version, label bounds, exact source extent,
source digest, seal, trailing bytes, and resource caps, then reparses original
BMP and shared BGP semantics. A persisted route projection never substitutes
for those bytes. Relationship assertions are analysis options and must be
supplied again to reproduce them. State/query/export use the normal BGP CLI
verbs and magic dispatch. Export includes source-order raw record rows, events,
normalized observations, and scoped RIB state; exact canonical NDJSON preflight
rejects one-byte-short output budgets before writing any export bytes.

Normal creation, fresh replay, state, query, and export use borrowed typed
projections. The exact output pass measures punctuation, escaped strings,
retained events and normalized observations by reference, cached CandidateState
encoding, and typed RIB versions/attributes/witnesses without a second aggregate
JSON tree. Export streams original record hex from fixed two-character byte
chunks. Writers preflight the complete body and any final newline before
mutating the writer. String-returning bounded methods reserve their measured
output fallibly after preflight. The public `json`, `bmp_rib_json`, and
`session_query_json` convenience tree constructors are explicitly outside this
bounded-method contract and are not used on normal publication paths.

## Proof charter and remaining qualification

`product/tests/bgp_bmp.rs` binds this contract to independently built tiny byte
witnesses: common/per-peer/OPEN range arithmetic; outer truncation at every
byte; malformed complete known messages; unsupported neighbors and extensions;
exact/one-unit-over input, record, peer, record-count, TLV, retained, work, and
output limits; ASN-format versus reported negotiation; regressing clocks;
source/checkpoint/distinguisher/policy non-collapse; peer-local and unscoped
quarantine; Peer Down reason 5; sealed restart/corruption/no-overwrite; and
fresh-process import/state/query/export through ordinary CLI entrypoints;
single canonical EOR application; required termination Reason with valid and
malformed controls; exact combined final retention and one-byte-below rejection;
and borrowed archive/query/RIB/export writer equality and atomic output caps.
The independent Python vectors in `product/tests/bgp_bmp_vectors.py` verify
wire arithmetic and flag/TLV namespaces without importing the Rust adapter.

Selectors describe planned acceptance obligations until the root records their
exact executed receipts. Independent review, integrated coherence, exact-head
platform CI, sustained fuzz, lawful collector/capture parity, scale/RSS, source
authenticity, and normative profile qualification remain separate evidence
dimensions. No green synthetic vector implies installed routes, negotiated
endpoint state, complete monitoring coverage, or network authority.
