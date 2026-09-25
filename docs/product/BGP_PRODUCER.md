# Bounded captured BGP producer contract

Source candidate against `9a90973d395305442f0aee435b224c31b9c31ae1`.
This extension governs direct captured decoding in `deep::bgp::decode_pcap`.
It does not replace [BGP_IMPORT.md](BGP_IMPORT.md), [BGP_STATE.md](BGP_STATE.md),
[BGP_REPLAY.md](BGP_REPLAY.md), or [BGP_ASSOCIATION.md](BGP_ASSOCIATION.md).
Native acceptance is **not established by the authoring worker**. See
[VALIDATION.md](VALIDATION.md); earlier receipts are historical evidence only.

## Ownership and entry points

`decode_pcap(&EvidenceBytes, PcapMetadata, &mut SessionState, &Limits)` retains its
signature and returns the existing `pcap-evidence.bgp.route-evidence.v1` envelope.
The private `bgp::producer` module owns captured admission, resource accounting,
OPEN evidence retention and transactional publication. No dependency, I/O,
source adapter, event type, CLI switch, socket, persistence, or external service
is introduced. Existing captured framing and imported normalization stay separate.

`PcapMetadata` has the same fields. Required source/record IDs and present
peer/local labels must be nonempty, non-whitespace, control-free and no longer
than `min(1024,input_bytes)` UTF-8 bytes. Direction is `None`, zero or one.
Session is the caller's optional numeric scope, not an endpoint identity.
`EvidenceBytes` must validate, have positive packet ordinals and one capture/run
namespace. Neither a source label nor a hash authenticates the original source.

A state becomes bound to `(source_id, session, PacketId.capture)` when it first
retains scoped evidence. Supplying a different known binding returns a typed
error. Reset advances a generation but does not authorize rebinding the state to
another source/session/capture. Construct a fresh `SessionState` for that case.
Peer/local labels remain per-observation evidence and are not inferred roles.
Capture direction and session are validated caller metadata: **BGP message bytes
alone cannot establish the TCP direction or session assignment**.

A missing direction cannot populate an OPEN direction-zero slot. A missing
session cannot populate state or borrow its OPENs/generation; the output generation
is null and `producer_context.scope_bound` is false. Such an envelope remains
observable but cannot enter the existing state consumer as a scoped captured
record. Missing direction with a known session retains the known generation.
A NOTIFICATION can close that explicitly supplied session without a direction;
its missing direction is reported, not filled in. A NOTIFICATION without a session
does not mutate another retained session. Signed timestamps are unchanged labels;
no clock ID, uncertainty, time zero, timing order or accuracy is manufactured.

`SessionState::generation()` is an additive read-only accessor. `reset()` remains
fallible on integer overflow. The state has private fields and supports equality
for explicit atomicity tests; no stable ABI claim is made.

## Transaction and resource boundary

The producer validates and stages the complete next state. It parses one complete
base BGP message, constructs bounded evidence, checks aggregate output structure,
checks exact serialized output size and retained-state accounting, and only then
replaces the caller's state and returns the value. Any error leaves the old state
unchanged and returns no partial normalized output. This includes a valid-looking
OPEN whose output budget is exhausted, and a NOTIFICATION whose generation would
overflow. There is no partial iterator, callback, hidden eviction, weaker retry,
or assertion that a rejected message was clean.

The existing `deep::Limits` are reused:

| Limit | Captured producer boundary |
|---|---|
| `input_bytes` | Original bytes, metadata totals and individual strings; bounded intermediate/public JSON encodings |
| `elements` | Aggregate routes, OPEN/capability occurrences, individual and aggregate typed path collections; issues include mandatory non-authority notes |
| `fields`, `depth` | Retained OPEN nodes, per-route replication preflight, complete JSON node/depth checks before publication |
| `spans` | Packet/span references, including retained OPEN witnesses and repeated references in the output |
| `active` | Retained OPEN direction slots; no silent removal when exhausted |
| `retained_bytes` | Logical retained OPEN metadata/witnesses, replicated route data and the final encoded output |
| `work` | One producer-call counter for source checks, retained-state scans/clones, bounded parsing, attribute comparisons, tree traversal, serialization and canonicalization |
| `output_bytes` | Exact complete encoded normalized envelope, checked before state commit |

The shared `Limits::default()` uses a depth budget of 32. That default accommodates
the nested packet-evidence and per-attribute occurrence witnesses emitted by this
producer while keeping the caller-visible maximum at 64; callers may lower it and
receive the same typed, atomic limit failure.

Checked arithmetic rejects overflow. Existing state is rechecked under new lower
limits before cloning. The scanner reserves bounded work before inspecting wire
structures; per-occurrence work and per-route replication are charged before the
corresponding copies. JSON escaping/serialization work is reserved before encoding.
Staging trees, typed records and encoded copies may coexist. These are conservative
logical budgets, not measured peak RSS, hard CPU instruction counts or an OS sandbox.
Some guard estimates deliberately reject a large input before its theoretical
maximum compact encoding could fit. No scale or throughput qualification is claimed.

The framing adapter still extracts the first complete frame and reports consumed
length; direct depth input must contain exactly one message. The base length is
19 through 4096 bytes. Direct decoding admits up to 65535 bytes for eligible
non-OPEN, non-KEEPALIVE messages only when the opposite-side receiver advertised
the extended-message capability in a complete, unambiguous pair of OPEN
observations. Eligibility is directional; the sender's own advertisement is not
authority for what the receiver accepts. The stateless outer framer carries
bounded messages up to 65535 bytes without choosing ADD-PATH or extended-message
grammar; the depth producer applies the retained receiver context. Expanded-
message PCAP depth behavior still needs a dedicated real-capture qualification
test.
The framing adapter's fixed attribute-count ceiling remains independently bounded;
this slice does not silently replace it with a larger depth limit. Attribute and
capability header reads cannot cross their enclosing declared block even when
neighboring message bytes would make a whole-buffer read possible.

## OPEN advertisements, not negotiated authority

The additive captured-only `producer_context` uses
`pcap-evidence.bgp.producer-context.v1`. Its ordered `open_sides` retain the full
source/record metadata, OPEN summary, exact original evidence spans/hashes and
all advertised capability/parameter occurrences for each direction. Retained
OPENs are not synthesized current-message bytes; their evidence has its own packet
references and local ranges. The current message still has its original envelope
`evidence`. No OPEN payload buffer is retained in state.

OPEN `message_detail` keeps the existing version, autonomous-system, hold-time,
identifier, four-octet-ASN and capability-code fields. `field_ranges`,
`parameters` and `capability_occurrences` identify exact message-relative
extents. RFC 9072 extended optional parameters are identified by the type-255
marker and decoded with their two-octet total and per-parameter lengths;
`extended_optional_parameters` records the selected wire encoding. Capability
occurrences preserve code, encoded length, enclosing parameter range, value
range, payload SHA-256, interpretation and repetition classification. The
additive `valid` and `invalid_reason` fields distinguish typed valid, typed
invalid and unknown occurrences. Unknown parameters/capabilities retain hashes
and raw codes/ranges without invented semantic values.

Typed advertisements cover multiprotocol (1), route refresh (2), extended
messages (6), role (9), graceful restart (64), four-octet ASN (65), ADD-PATH
(69), enhanced route refresh (70) and LLGR (71). Family tuples, flags, timers,
ADD-PATH send/receive modes and roles retain their occurrence byte ranges.
Four-octet ASN `decoded` remains an advertised unsigned scalar for compatibility.
Invalid declared lengths and values remain hashed occurrences with a reason.
Identical duplicate capabilities remain separate evidence; conflicting ASN,
role or ADD-PATH advertisements do not select a grammar. Inconsistent base-ASN
and advertised-ASN fields, AS zero and invalid base hold-time labels remain
explicit ambiguous evidence. Different ASNs advertised by opposite directions
are ordinary independent advertisements, not a conflict.

A different OPEN observation in a previously populated direction no longer
silently advances the generation or deletes the opposite side. Both observations
remain retained and the context becomes ambiguous. Only the existing explicit
reset or a scoped NOTIFICATION retires that generation. Re-presenting the exact
same immutable OPEN witness does not append state. Identical wire content in a
different captured record remains a separate observation; it is not assumed to
be a retransmission epoch. Historical outputs are immutable snapshots, not promises
that later contradictory evidence cannot change the current interpretation.

When exactly one unambiguous OPEN is retained for each direction, both advertising
four-octet-ASN support supply a four-byte **layout context**; otherwise a complete
bilateral base advertisement supplies a two-byte layout context. The additive
`capability_layout` also records bilateral multiprotocol families, directional
ADD-PATH layout, unresolved ADD-PATH families, per-sender extended-message
eligibility and a compatibility-only bilateral extended-message summary.
ADD-PATH layout requires the sender's send mode and the peer's receive mode for
the same AFI/SAFI. A unilateral or malformed ADD-PATH advertisement leaves the
affected NLRI opaque with range and hash evidence. No ADD-PATH evidence retains
the legacy wire-shape hypothesis for compatibility. This context does not prove
negotiation, actual session establishment, authenticity or endpoint behavior.
With absent context the decoder retains both valid bounded AS_PATH interpretations.
A unique wire interpretation, or identical values from both interpretations, may
supply byte-derived values while width authority stays unresolved. Different valid
interpretations leave the scalar path summary empty and retain both alternatives.
Unusable capability context likewise cannot authorize a scalar AS_PATH/AGGREGATOR
winner. The historical `asn_width_derived_from_two_octet_default_or_open` issue
remains readable, but callers must consult the new explicit interpretation/basis;
it is not a negotiation certificate.

Unsupported session capabilities are reported again on UPDATE evidence. Typed
capability decoding and bounded layout hypotheses do not cover arbitrary future
capabilities, specialized AFI/SAFI payloads or endpoint session adjudication.

## Path occurrence evidence and summaries

Every path attribute is retained in ordered `attribute_ranges`, both per route and
once in UPDATE `message_detail`. Consequently an UPDATE with no prefixes does not
lose its path-attribute evidence. Existing type/flags/start/end/payload-digest
fields retain their meanings. New `value_start`, `value_end`, `decoded`,
`interpretation` and `repetition` fields describe the same occurrence, not another
attribute or an authoritative replacement path.

The first occurrence is the only semantic candidate and is subjected to its own
validation; when valid and supported, it populates the effective scalar/list
summary. Each later ordinary duplicate is discarded for semantics under
[RFC 7606](https://www.rfc-editor.org/rfc/rfc7606.html#section-3), without
replacing or concatenating the first value. All occurrence values remain present
in order with an explicit `discard_later_occurrence` disposition. The
`repetition` field independently records whether a later occurrence is bytewise
identical (`duplicate_identical`) or differs (`conflicting`); that diagnostic
does not make the effective first value ambiguous. Repeated MP_REACH_NLRI or
MP_UNREACH_NLRI instead has a session-reset disposition. Unknown types remain
`unsupported` with hash/range identity. Phase 1 retains AS4_PATH and
AS4_AGGREGATOR occurrences while the UPDATE detail reports the RFC 6793
reconstruction/discard basis and effective candidate path separately.
Known-width
AGGREGATOR supports the already represented two/four-byte context. A simultaneous
base NEXT_HOP and MP_REACH next hop is not silently collapsed into one scalar:
the summary is null and family-specific occurrences remain unresolved alternatives.

A range is relative to its own original message. Compose it with that message's
EvidenceBytes spans to locate contributing packet offsets; do not apply retained
OPEN offsets to an UPDATE. Payload hashes cover the exact attribute value bytes.
Attribute metadata, flags, lengths, multiplicity and missing mandatory fields now
produce occurrence and UPDATE-level evidence dispositions using RFC 7606 labels.
`update_disposition`, `missing_mandatory`, `as4_reconstruction` and `opaque_nlri`
are evidence summaries. The producer enforces those summaries at its state seam:
`treat_as_withdraw` converts every emitted announcement in that UPDATE to a
withdrawal, while `session_reset` suppresses every route action and retains each
affected route range/hash as opaque evidence. A malformed UPDATE with path
attributes but no reachable NLRI escalates from treat-as-withdraw to session reset.
This models the required offline disposition without claiming that a NOTIFICATION
was sent, a peer reset, or an endpoint route changed. COMMUNITIES,
EXTENDED_COMMUNITIES and LARGE_COMMUNITY require nonzero correctly aligned values;
their malformed forms are treat-as-withdraw. Malformed AS4_PATH is attribute
discard. MP_REACH/MP_UNREACH route semantics require the bilateral AFI/SAFI
capability; otherwise the occurrence stays range/hash-visible and no route is
emitted.

The producer labels a conventional empty UPDATE and a negotiated empty
MP_UNREACH as explicit End-of-RIB families. A NOTIFICATION or UPDATE whose
strongest RFC disposition is `session_reset` advances the staged decoder
generation only after complete output/budget validation. The atomic captured
pipeline consumes that exact transition; it does not infer a reset from elapsed
time or a missing packet.

The two bounded downstream repairs are coordinate-specific: state admission
validates supplied value extents, and state/association path identity excludes
`value_start`/`value_end` just as it already excluded the outer coordinates. The
coordinates remain in normalized evidence. Moving an otherwise identical path in
its packet must not create a different path. Unresolved width/capability/next-hop
interpretations are marked ambiguous by the state consumer. Unknown non-coordinate
attribute fields still participate in conservative identity; sources are never voted.

## Compatibility, replay and association

Imported normalization, full import context, immutable batch/checkpoint identity,
clock labels, explicit generation transitions, feed ordering, cursor commitments,
replay receipts and association policies are not changed. The imported API is not
made to fabricate captured producer context. Legacy and contextual imported output
bytes are intentionally unchanged by this patch. Captured/imported values retain
the same route-evidence schema, not interchangeable provenance or authority.

Captured output gains `producer_context`, UPDATE occurrence metadata and explicit
false claims; encoded captured event hashes change. Missing-session captured
generation is now null. Repeated-OPEN generation behavior intentionally changes
from inferred replacement to retained ambiguity. Strict consumers must accept
these additions and inspect ambiguity/issues instead of relying on scalar values.
Do not rehash old producer artifacts as though produced by this version.

No replay path accepts a captured record as an imported feed record. Association
can consume the current normalized shape or candidate snapshots without mutating
them; its namespace/dimension/time policy, coverage limitations and imported-clock
override prohibition remain authoritative. Source kind is never a preference.
Every captured output keeps endpoint, RIB, best-path, reachability, attack,
causality, source-authority, negotiation and normative claims false.

## Review and remaining work

The pinned replay source retains explicit page order, partition declarations,
predecessor checks, conflict quarantine, coverage meet and staged CandidateState
application. It intentionally does not fix the captured producer. This extension
addresses that producer boundary and the new coordinate-sensitive consumer seam.
The review was not clean: producer budgets/state mutation, unbound source/session
reuse, unilateral width selection, implicit repeated-OPEN epochs, overwritten
scalar values and route-free attribute loss required changes.

Replay's `encode` path now reserves its complete logical accounting before
publication and retains atomic failure receipts. Its helper accounting remains a
separate implementation from this producer's single-call accounting, but the
previous uncharged-serialization finding is repaired and covered by focused
replay tests; it is no longer an open defect.
Source authentication, actual imported-byte verification, reliable automatic sink
boundary/generation forwarding, specialized capability-dependent wire grammar,
session adjudication and route-state reduction, broad operational
corpus, cross-platform runtime, scale, sustained fuzz and production qualification
remain open. Conservative identity tokens may differ when decoding context changes
even when some scalar values agree; no equivalence is silently invented.

Wire layout reasoning uses RFC 4271 section 4, RFC 5492 section 4, RFC 6793
sections 3 through 6, RFC 7606 sections 3 through 7, RFC 7911 sections 3 through
5, RFC 8654 sections 2 through 4, RFC 9072 section 2 and the current IANA
Capability Codes registry. Advertisement values are not votes, and NEW-to-NEW
versus NEW-to-OLD encoding is not determined by a single observed speaker.

## Tests and validation

`product/tests/bgp_producer.rs` adds 37 integration-test functions and the private
producer has five focused unit tests. The fixed `bgp_producer.hex` vectors and eight
independent Python checks cover exact lengths/ranges, conflicting occurrences,
two/four-byte values and two distinct valid AS_PATH interpretations. Python uses
only its standard library and does not import or execute the Rust decoder.
Phase 1 adds `bgp_phase1.rs` and `bgp_phase1_vectors.py` with hand-built
capability, AS4, ADD-PATH, attribute, refresh, boundary and provenance cases.
The typed ASN4 OPEN occurrence also passes through a generated, handshake-bearing
PCAP into `pcap-depth` output; larger extended UPDATEs have a framer/direct-decoder
test but no equivalent PCAP receipt yet.

Required native runs include the new producer target, existing BGP import/state/
replay/association and producer unit tests, real `pcap-depth` regression, root,
product and streaming fmt/check/build/test/Clippy, release and feature matrices.
The authoring worker lacked the Rust toolchain, so its Python/static/patch checks
were not native proof. The integrator then repaired one default-depth compatibility
issue and six Clippy test-fixture issues in an isolated Windows checkout. Fresh
native format, workspace check/test/Clippy, product release test/Clippy, vector,
root validation and portable product gates now pass for this slice. No new Linux
runtime, live, scale, fuzz, secure, external-source verification, adapter or
normative qualification is claimed.
