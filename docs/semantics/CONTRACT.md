# Tier-A semantic subset v1

This is an additive parser-library slice. It does not replace capture, TCP,
fragment, message-framing, correlation, history, or product ownership. It adds
bounded native field reports over existing `EvidenceBytes` and integrates their
JSON projection into snapshot reports and streaming/product messages. The product
TLV writer encodes the resulting existing `Json` value model without a new binary
record format or a dependency on another parser.

## API and observation scope

`semantics::dnp3::decode` accepts one application fragment's **object region** and
an explicit function context. `fragment_json` verifies that the public fragment's
function/control/object bytes and spans agree with its raw fragment before using
that context. CRC validation and stream/application reconstruction remain owned
by the existing DNP3 engine. Never join the object bytes of separate application
fragments and then call this decoder as if they were one fragment.

`semantics::modbus::decode` accepts exactly one MBAP-framed ADU and an explicit
request/response role. `alternatives_json` keeps both interpretations when that
role is unknown, including rejected alternatives. A server port remains a
caller/configuration role hint, not proof of endpoint behavior. `check_pair` tests
an explicitly supplied pair; it never searches for or creates a transaction.

Reports borrow immutable source evidence. Private native record/field members and
read-only accessors keep source ranges validated. Each field contains a typed
value, half-open input range, exact contributing packet offsets, and source-byte
SHA-256. Calculated range indices identify their derivation; a count-only object
does not invent a point index. Duplicate object indices remain separate records.
Packed values retain their bit position within the witnessed byte (LSB is bit 0).

Raw source hashes identify bytes, not authenticity, conformance, or authorship.
Capture/run source binding remains owned by the parent envelope. Unsupported or
truncated tails retain a byte range, hash, and packet spans, without raw payload
hex being exported by this extension.

## DNP3 subset

| Object family | Value variations |
|---|---|
| Binary input / binary output status | g1/g10 v1 packed, v2 flags |
| Binary input events | g2 v1 flags; v2 raw absolute 48-bit ms; v3 unresolved relative 16-bit ms |
| Counters | g20 v1/v2 flags plus u32/u16; v5/v6 without flags |
| Analog input | g30 v1/v2 flagged i32/i16; v3/v4 unflagged i32/i16; v5/v6 flagged float bit patterns |
| Time | g50 v1, g51 v1/v2 raw 48-bit millisecond quantity |
| Device attributes | g0 specific variations and g0v255 list envelopes; typed u/s integers, IEEE bit-pattern floats, known signed-int booleans, raw 48-bit time | strings/octet/bit/list values hash-only; unknown/private/security meaning is not inferred |

READ headers cover those variations, wildcard v0 for g1/g2/g10/g20/g30, and
class g60 v1–v4. Header syntax supports qualifiers 00/01 (8/16-bit range), 06
(all objects, headers only), 07/08 (8/16-bit count), and 17/28 (matching count and
index widths for response values). READ index lists remain unsupported. Packed
responses require range qualifiers in this subset. General qualifier syntax
support is **not** an assertion that every group/qualifier/function combination
is mandated by the normative specification or accepted by endpoints.

Unknown widths/qualifiers, all-object responses without a count, variation-zero
response data, controls, writes, authentication, Group 70 authentication variation 2,
vendor data, secure meaning, and other groups stop with an explicit unsupported
tail. Group 70 qualifier 0x5B file-object variations 3--8 are a bounded exception:
command/status, transport and descriptor metadata are source-bound to exact spans,
while filename, file-specification, authentication-key, and content bytes are
hash-only and no transfer conversation or file effect is inferred. Group 0
attribute envelopes are bounded
as described above; there is no speculative
resynchronization and no state carried between application fragments. Flags stay
raw. Float32/64 values stay exact bit patterns, including NaN payloads and signed
zero. Relative event times are not resolved against a guessed common time.

## Modbus subset and intentional correction

Functions 1–6, 15, and 16 expose wire addresses, quantities, packed coil octets,
individual write-coil values, u16 register values, and supported exception codes.
Addresses are zero-based protocol addresses, not the conventional 4xxxx notation.
Register scaling, signed interpretation, cross-register float/string layouts,
device identity/register maps, physical effects, and successful command execution
are not inferred.

A read-bit response alone contains byte count, not exact requested bit count.
It therefore emits packed response octets rather than guessing padding bits as
additional coils. A read-register response similarly does not invent addresses.
An explicit paired request can supply those constraints for consistency checks.

**Behavior correction:** `modbus::response_matches` now rejects nonzero unused
high-order bits of FC1/FC2 responses when a validated request supplies the bit
count. Streaming correlation retains quantity, response byte count, and last
response octet in versioned internal tokens and enforces the same constraint.
FC15 request padding has a zero-fill recommendation; nonzero padding is a warning,
not a newly invented mandatory rejection. Exceptions retain the existing
compatibility wildcard. Neither matching identifiers nor valid padding proves
causality or endpoint success.

FC20 and FC21 expose ordered file records. FC22 exposes the address and both
masks. FC23 distinguishes read and write ranges and FC24 exposes FIFO counts
and words. FC43/14 returns one page of device-identification objects with value
lengths, hashes and byte spans. For nonempty values, the unsigned
`object_value_octet_count` covers the value bytes. Its v1 field evidence
contains their SHA-256 digest and packet spans. The unknown-direction decoder retains both
role interpretations. Other MEI types remain opaque.

A partial MBAP blocks candidate pairs sharing the captured transaction-ID,
unit and function prefix. Lost framing leaves the whole connection in doubt.
An exception to FC43 omits the MEI type, so a competing opaque MEI request
with the same identifiers also prevents a unique pair. A capture clock
reversal alone preserves snapshot pairs when transport evidence is contiguous.
Streaming retains its window-wide ambiguity policy for clock diagnostics.

For FC43/14 stream access, basic object IDs 0 through 2 are mandatory. A page
starting within that sequence must return consecutive IDs up to object 2
or identify the next mandatory object on a subsequent page. Extended function
exceptions accept file parity error 08 only for FC20/21. Legacy function
exception decoding preserves its original code set.

Finalized compatible FC1–4 and FC23 reads carry a compact `read_mapping`.
Value index zero corresponds to the starting address. The quantity bounds the
meaningful response values, including the final packed octet of a bit read.
The mapping names both observations and their ADU offsets. Midstream pairs
carry `candidate_unverified_boundary` on the mapping itself. Exceptions and
ambiguous groups have no read mapping. History queries retain standalone
interpretations because a query selects one TCP direction.

## Status and limits

`decoded_subset` means the selected field decoder consumed this input under its
subset rules. It does not certify normative or device semantics. Other statuses
are `incomplete`, `unsupported`, `rejected`, and `limit_exceeded`. Complete earlier
records survive a stopped tail. `consumed` is a safe parser prefix, not a claim
that partially inspected bits after it were never observed.

Default logical limits: 64 KiB input, 2048 records, 8192 fields, 16384 source-span
references, 1,048,576 work units, 4 MiB nested JSON. Parent capture application and
message budgets can only reduce the derived defaults. In streaming, each Modbus
ADU must fit the application byte limit. Both directions of a TCP generation
share the native message allowance within its window. When the allowance binds,
frames are admitted in order of the last contributing capture record. An over-limit ADU
produces a scoped issue before field decoding and transaction matching. These are finite logical
bounds, not OS-enforced RSS or CPU sandbox limits. Output trees and a bounded
serialized validation copy can coexist. The parent event/report output cap still
applies and can reject an expanded report rather than silently omit fields.

Legacy framing fields, `complete`, parent event statuses, and the legacy global
`object_semantics: opaque` label keep their earlier meaning: framing completeness
and lack of full device/object semantics. The new nested subset status is separate.
`--require-clean` continues to describe the pre-existing pipeline diagnostics;
consumers must also inspect the additive semantic statuses. A future versioned
aggregate diagnostic policy may incorporate them; this slice does not silently
change that contract.

## Compatibility and outputs

The existing envelope schemas stay at v1. New optional nested fields are:

- Snapshot DNP3 application fragment: `object_semantic_subset`.
- Snapshot Modbus message: `semantic_subset`.
- Streaming DNP3 message: ordered `object_semantic_subsets` keyed by fragment index,
  plus exact `application_fragment_evidence` and the assembled
  `application_object_evidence` used by opt-in depth consumers.
- Streaming Modbus message: `semantic_subset`.

The nested schemas are `pcap-evidence.semantic-subset.v1` and
`pcap-evidence.modbus-alternatives.v1`; `semantic.schema.json` describes them.
Strict consumers that disallow additive application-data fields must update or
version their projection. Exact serialized outputs and event hashes change;
regenerate source-bound projections and fixtures rather than rehashing old logs
as if they came from the new producer. No old evidence is edited by the installer.

Normative edition review, independent expert adjudication, and broad external
analyzer equivalence are NOT established by this implementation or its case list.

The snapshot and streaming correlators withhold Modbus enrichment for every
generation that could own an unassigned TCP data segment. When snaplen removes
transport data but the captured IP and TCP headers identify a plausible
generation, the same restriction applies, including when the snapped header precedes
the first complete segment. Streaming uses the observed tunnel path to distinguish
otherwise identical connections. Offset-zero fragments and partial TCP options
can supply a TCP identity for loss attribution once the first 14 TCP bytes
are captured. The ordinary decoder requires the complete header and options. A pending first fragment
counts toward the streaming packet window and withholds enrichment for plausible
generations. When such a header forces a capacity cut, it also applies to the
closing window. Reassembly resolves its own fragment observations, including
duplicate fragments in enclosing tunnels. Under strict checksum checking, a
completed segment rejected for its checksum has the same disposition whether
it arrived whole or in fragments. A provisional fragment consumes a packet slot until adjudication. Its timestamp cannot trigger or renew an idle cut in an existing
window. Idle decisions use the timestamps of admitted segments and confirmed
omissions. A pending header is matched against the final admitted activity of
each candidate generation. A definitive rejection on the record that expires a
window releases its fragment witness before the window publishes pairs.
Identical IPv4 fragment overlaps retain the witness from the lowest starting
offset, with arrival order breaking ties. Partial IP payloads can supply a header
witness, but normal transport decoding and fragment admission require the
complete declared extent. Adjacent fragments can jointly identify a TCP header
before reassembly finishes. A gap before the identity fields leaves the header
unknown. If the fragment limit interrupts assembly, streaming can still use
the arriving fragment and retained contiguous bytes to identify which TCP
generation lost evidence. An IPv6 extension header after the fragment header
can identify the inner protocol while the enclosing datagram is still incomplete.
If the whole checksum-covered extent is available on
a refused arrival, strict mode can resolve the loss witness from its checksum.
For an incomplete UDP tunnel, strict mode rechecks the checksum when all declared
UDP bytes become contiguous, even if the enclosing IP datagram still lacks bytes.
An identical first fragment reuses that verdict and retains its own packet
reference. A change to the terminal extent or checksum context triggers a new
inspection.
An assembled segment replaces its provisional contributors before the window
checks its idle and capacity limits. When a complete set is refused by the
fragment or window allowance, the completion time determines which generations
receive the confirmed omission. Tunnel loss
attribution honors enclosing IP and UDP lengths. Both captured and omitted payload must start at or after a
generation's first payload sequence when that direction has an observed SYN.
The comparison uses TCP sequence arithmetic and applies in either arrival order.
If a snapped FIN lacks options but its declared lengths establish an empty
payload, its sequence still supplies a possible stream end. A discrepancy with
the retained data end or an admitted FIN withholds the affected mapping. A FIN
at the established end preserves it. A terminal IP fragment can establish this
extent while TCP options are still missing. A pending ACK with a known empty
payload contributes no stream end. Both decisions depend on the fragment set.
If conflicting fragments quarantine it, both earlier headers and a TCP header
first identified on the conflicting arrival represent possible payload loss
for their candidate generations. This also applies to inner TCP headers in a
fragmented tunnel. A reassembled FIN refused at the
window’s packet-reference limit supplies the same end-position evidence.
A late handshake rechecks earlier stream positions and loss observations against
the observed initial sequence and configured span. Excluded packets remain in
diagnostics. A SYN-ACK must acknowledge the peer SYN when it was observed.
The ACK can cover any prefix of data carried on that SYN. A retransmission
with the same initial sequence can extend that range. Omitted headers use the
final observed range in either capture order. The comparison
uses wrapping sequence arithmetic ([RFC 9293 §3.10.7.3](https://www.rfc-editor.org/rfc/rfc9293.html#section-3.10.7.3)).
When the ACK is in range, the SYN-ACK sequence
establishes the missing origin even if an earlier segment lay outside that span.
It can overturn a tentative two-FIN close if all FINs for the unanchored
direction fall outside the new sequence interval. The tracker indexes those FIN
positions until that direction gains a SYN. A captured SYN-ACK header with
omitted data can establish the same possible ownership, so its missing bytes
withhold the mapping without changing the observed handshake. The tracker
evaluates omitted handshakes against the corrected close position at their
arrival. A later FIN or reset cannot erase an earlier loss witness. A genuine
earlier close excludes an omitted opening SYN retransmission.
Window and active payload limits count the bytes the tracker
retains after that correction. The tracker reserves loss observations for
displaced payload before changing the flow. If the attribution exceeds its
work or retention budget, streaming emits `capture.aborted` before publishing
transactions from that window.
A complete payload-free control resolves provisional payload evidence even
when its own generation assignment remains ambiguous.

Losing only the options of a header-only TCP segment preserves payload
eligibility. Unassigned data and segments too large for a streaming window
also contribute header evidence. A disjoint successor generation can still
produce pairs. Ambiguous application groups reference competing messages
and framing issues in the snapshot, and their event IDs in streaming output.

FC20 uses the 245-byte response data ceiling in V1.1b3 §6.14. A single record
can therefore return up to 121 words. For the lower bound, the parser follows
the specified word layout and the worked example, whose subresponse length
is 5 even though the table lists 7 as its minimum. It accepts a one-word
subresponse of length 3. A malformed record or outer byte count yields a
rejected PDU. Complete preceding records retain their witnesses within the
declared count, the available bytes and the function's size limit. For the
extended functions, missing fields inside a complete MBAP extent reject the
PDU. A capture ending before the declared ADU length is incomplete. FC43/14 accepts a restart at object 0
only if the requested ID is optional and absent from the observed page.
Role alternatives share the caller's record, field, span and work budgets.
Undecoded tails count toward the span budget. If the remaining allowance cannot
represent the whole tail, its evidence retains the byte digest and an empty
span list. The bounded issues list records `semantic_tail_spans` when it has room.

The snapshot CLI encodes report rows against a single byte allowance including
protocol detection and the trailing newline. It publishes output only after the
whole report fits. Library callers that need an editable JSON tree can use
`report::analysis`. A finalized Modbus pair with a changed public reference
is omitted from the snapshot's transaction candidates.

History application replay shares its frame allowance across the selected
range, including page boundaries. At exhaustion, earlier reports remain in
order and the terminal record identifies the last completed output boundary.
