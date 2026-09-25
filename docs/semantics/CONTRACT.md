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

## Status and limits

`decoded_subset` means the selected field decoder consumed this input under its
subset rules. It does not certify normative or device semantics. Other statuses
are `incomplete`, `unsupported`, `rejected`, and `limit_exceeded`. Complete earlier
records survive a stopped tail. `consumed` is a safe parser prefix, not a claim
that partially inspected bits after it were never observed.

Default logical limits: 64 KiB input, 2048 records, 8192 fields, 16384 source-span
references, 1,048,576 work units, 4 MiB nested JSON. Parent capture application and
message budgets can only reduce the derived defaults. These are finite logical
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
