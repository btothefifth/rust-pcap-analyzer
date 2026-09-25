# Implemented binary formats

This is an implementation guide, not a replacement for the pinned specifications in
`SOURCES.md`. Format support and semantic protocol support are different capabilities.

## Classic PCAP

File header: **24 bytes**. Offsets 0/4/6/8/12/16/20 contain magic(u32), major(u16),
minor(u16), reserved1(u32), reserved2(u32), snaplen(u32), link-type/flags(u32).
This implementation accepts version 2.4 and nonzero snaplen. Historical reserved
fields are retained in raw bytes, not interpreted as a mandatory timezone correction.

| Magic bytes on disk | Endian | Fractional timestamp unit |
|---|---|---|
| A1 B2 C3 D4 | big | microseconds |
| D4 C3 B2 A1 | little | microseconds |
| A1 B2 3C 4D | big | nanoseconds |
| 4D 3C B2 A1 | little | nanoseconds |

Each record is **16 bytes** of seconds(u32), fraction(u32), captured length(u32),
original length(u32), then exactly `captured_length` bytes. No inter-record padding.
The upper link-field flags are preserved; they do not become the LINKTYPE value.
Captured length, not claimed wire length, bounds accessible bytes.

## PCAPNG

A block contains type(u32), total length(u32), aligned body, and the same trailing
total length(u32). The total is at least 12, a multiple of four, and within configured
bounds. Leading/trailing lengths must agree. Each block's specific minimum is also
checked. Unknown block bodies are preserved.

A Section Header Block begins with endian-invariant bytes `0A 0D 0D 0A`. Inspect the
byte-order magic at offset 8 (`1A 2B 3C 4D` or its reverse) before interpreting its
length or remaining multibyte fields. This implementation accepts version 1.0.
A new section resets its interface namespace and endian state. A known section length
is checked against subsequent boundaries; -1 means unspecified.

IDBs implicitly number interfaces from zero **inside a section**. Each carries a
link type, snaplen and options. Snaplen zero in PCAPNG means no capture limit.
Interface `if_tsresol` defaults to decimal exponent 6. A zero high bit means
`10^-N` seconds per tick; a set high bit means `2^-N`, using the other seven bits.
`if_tsoffset` is a signed seconds offset. Packet timestamp high/low fields form
`(high << 32) | low`, not a seconds/fraction pair.

EPB (type6) body: interface(u32), time high(u32), time low(u32), captured length(u32),
original length(u32), packet bytes, four-byte alignment padding, options. PB(type2)
is the obsolete packet variant. SPB(type3) uses the first interface, has no timestamp,
and its captured size is constrained by original length and snaplen. Padding is
never returned as packet payload.

Options are code(u16), length(u16), value bytes and alignment padding. End-of-options
is code0/length0. Unknown codes and their raw values survive parsing. The library
validates framing but does not promise a typed semantic decoder for every registered
or vendor-specific option.

Metadata block families include Name Resolution(type4), Interface Statistics(type5),
Decryption Secrets(type0x0A), custom(type0x00000BAD), and do-not-copy custom
(type0x40000BAD). Raw capture copying preserves bytes exactly; that archival operation
is not semantic merging/editing of do-not-copy custom blocks. JSON never includes
embedded decryption-secret bytes.

## Exact clock conversion

The canonical value is `Timestamp { ticks: u64, resolution, offset_seconds: i64 }`.
Exact Unix nanosecond projection returns an integer only when no precision would be
lost and the value is representable. Fractional nanoseconds return `InexactTimestamp`;
the original raw operands remain usable. Binary-resolution tick1025 with exponent10,
for example, cannot be exactly expressed as integer nanoseconds.

Classic writing rejects negative or out-of-u32 seconds and sub-microsecond loss when
using the microsecond format. Reading does not use floats or a guessed clock offset.

## Sidecar v1: `PCIDX001`

All integer fields are little-endian. Header **56 bytes**:

| Offset | Bytes | Meaning |
|---|---|---|
| 0 | 8 | ASCII `PCIDX001` |
| 8 | 8 | source length |
| 16 | 32 | source SHA-256 |
| 48 | 8 | packet entry count |

Each entry is **64 bytes**:

| Offset | Bytes | Meaning |
|---|---|---|
| 0 | 8 | raw record offset in source |
| 8 | 4 | raw record length |
| 12 | 4 | packet-data offset relative to raw record |
| 16 | 4 | captured length |
| 20 | 4 | original length |
| 24 | 8 | 1-based packet ordinal |
| 32 | 4 | section ordinal |
| 36 | 4 | interface ordinal within section |
| 40 | 4 | link type |
| 44 | 1 | timestamp presence |
| 45 | 1 | encoded PCAPNG-style resolution |
| 46 | 2 | reserved zero |
| 48 | 8 | raw timestamp ticks |
| 56 | 8 | signed seconds offset (two's complement) |

Absent timestamps zero the final 20 bytes. A final **32-byte SHA-256** covers the
header and entries. Total length is `56 + 64*count + 32`.

Hashes are not authority. `VerifiedIndex::load` verifies the source hash and rebuilds
an index from the immutable source, then compares the complete canonical encoding.
An attacker cannot authorize an offset merely by rehashing a forged index. Loading
is intentionally O(source bytes); repeated lookup is direct after validation. Time
queries scan entries and separately return timestamps that cannot be resolved.

## Analysis report additions

The versioned analysis report keeps TCP applications under `applications` and places
configured-port UDP DNP3 observations under `udp_applications`. Each UDP entry has
its own source/destination, scoped interface/VLAN identity, contributing packet IDs,
payload evidence spans and nested DNP3 result. The nested result may be incomplete or
diagnostic; a present entry is not a claim that a complete message was reconstructed.

UDP entries are datagram-local. The report never presents multiple UDP datagrams as
one reliable byte stream and does not create a cross-datagram transaction merely from
matching addresses or application sequences. Advisory protocol-probe results are
separate from this dispatch field and are not serialized as protocol authority.
