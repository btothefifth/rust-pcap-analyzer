# Typed evidence TLV v1

The Rust output module and independent Python reader/writer encode the same event
model using typed values, not JSON text inside a binary blob. This is a versioned
candidate format; retain golden vectors and compatibility tests before freezing it
as a downstream ABI. The root NDJSON event schema remains unchanged.

## Envelope

Magic: ASCII `PCEVTLV1` (8 bytes). Each subsequent record is:

| Field | Encoding |
|---|---|
| record_length | big-endian u32, bytes after this length field |
| sequence | big-endian u64, starts at 1 |
| previous_hash | 32 bytes, all zero for first record |
| event_hash | 32 bytes |
| typed_event | exactly one typed object |

The hash is SHA-256 of `pcap-evidence/tlv/v1` + NUL + previous_hash + sequence's
8 encoded bytes + typed_event. It is distinct from NDJSON's hash domain and exact
encoding; compare decoded events when testing cross-format semantics. It is an
integrity chain, not a signature or proof of parser correctness.

## Typed node

Each node is tag:u8 + length:BEu32 + body. Tags: 0 null (zero length), 1 boolean
(one byte, 0 or 1), 2 unsigned u64 (8 bytes BE), 3 UTF-8 string, 4 ordered array of
nodes, 5 ordered alternating string-key/value nodes. Object keys must be unique.
Unknown tags 6–255 are retained by the Python reader as `Opaque(tag, bytes)`;
consumers cannot silently treat their semantics as understood. Wrong lengths,
truncated values, invalid UTF-8, duplicate keys and trailing nodes reject.

Example: u64 258 is `02 00000008 0000000000000102`.
All long identities, positions and nanosecond times in event fields remain decimal
strings under the inherited event model, including values outside JavaScript's
safe integer range. Binary scalar u64 does not license changing those field meanings.

Default record cap: 8 MiB including framing, depth 24, node count 100,000. Limits
are checked before record reads and during encoding. Unknown values remain bounded.
Reader requires `capture.start`, contiguous sequence/run identity and by default a
terminal `capture.complete`. Partial/aborted reading must be explicit. Records after
a terminal event reject. A successful sink write is not successful source binding
until the producer's terminal source evidence has also been checked.

Generic `Write`/BinaryIO may fail partially. Writers do not silently accept a zero-
progress or short write. Discard partial output or mark it unbound; never resume as
though the prior operation wrote nothing. Rust/Python byte parity and native sink
failure injection remain integration gates where the compiler is available.
