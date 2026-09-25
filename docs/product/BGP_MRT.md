# MRT adapter v1

Owner: `product/src/deep/bgp_mrt.rs`. This is the Phase 4 MRT container
slice under [BGP_COMPLETION.md](BGP_COMPLETION.md), criterion BGP-C08.
The primary byte layouts are RFC 6396 sections 2–4 and RFC 8050 for
ADD-PATH subtype numbers. The adapter takes an already available byte slice.
It downloads nothing and makes no claim that a collector label, digest, or
successful parse authenticates the source.

## Record and conversion contract

- Each record retains source-relative common-header offset, declared body
  length, type, subtype, timestamp seconds, ET microseconds when present, and
  SHA-256 over the exact common header and body. The batch retains byte length
  and SHA-256 over the exact input. Unsupported records retain their bounded
  body bytes and an explicit reason.
- TABLE_DUMP_V2 subtype 1 retains the full peer table, its own record identity,
  peer-index order, peer address, ASN, and ASN-field width. Subtypes 2, 4 and 6
  decode IPv4/IPv6 unicast RIBs only. Each entry retains its original
  attribute bytes, zero-based peer index, originated seconds, and sequence.
  The sequence is scoped by batch, peer-table record identity and the caller's
  checkpoint label. Unknown AFI/SAFI has no assumed NLRI or entry-count
  boundary and remains opaque. The view name must be UTF-8, and the table is
  scoped only to the immediately following TABLE_DUMP_V2 RIB series; an
  unrelated record ends the association.
- BGP4MP and BGP4MP_ET state and message subtypes retain peer/local address
  and ASN, ASN-field width selected by subtype, interface index, locally
  generated and ADD-PATH subtype labels, and either raw state numbers or one
  exactly framed BGP message. The ET microsecond field is part of the MRT
  body length. A BGP4MP address AFI does not label the message's route family.
- `MrtBatch::normalize_rib_entry` converts only the unambiguous subset of
  ordinary RIB attributes into the existing contextual imported route
  envelope. The peer-table digest and index remain in the peer partition;
  the sequence and table offset remain in the checkpoint; the exact MRT
  record range and digest remain in import provenance. Source and batch
  identities remain distinct from captured evidence. Direction remains
  unknown, so this envelope cannot establish session or Adj-RIB-In state.
  Unsupported, duplicate, malformed-value, or MRT-special attributes return
  `None` for semantic conversion while the versioned MRT record keeps the
  original bytes. In particular, RIB AS_PATH uses four-byte ASN elements and
  abbreviated RIB MP_REACH_NLRI cannot be decoded as an UPDATE attribute.
- BGP4MP message bytes are a versioned imported-message conversion seam.
  The current packet decoder requires real packet provenance; supplying a
  synthetic packet would falsely label collector bytes as captured evidence.
  Message-to-imported-wire normalization is a remaining Phase 4 dependency.
  There is no BMP adapter in this slice.

## Bounds and acceptance

`MrtLimits` has finite input, record, peer, entry, prefix, attribute,
retained-byte, work, and output allocation charges. The parser preflights
common-header lengths and record count, then enforces semantic limits before
allocating each peer/entry/raw payload. It publishes one `MrtBatch` only
after every record succeeds. Truncated fields, invalid indexes, contradictory
lengths, overflow, trailing partial headers, empty input, and over-budget input
fail with no partial result. The output charge is an allocation bound for this typed
adapter, not a byte count for a future JSON encoding.

The test charter is: hand-built byte arithmetic and truncation at every
boundary in `product/tests/bgp_mrt_vectors.py`; native typed-record,
conversion, opaque-neighbor, index, ET, and exact/one-below budget tests in
`product/tests/bgp_mrt.rs`. A future Phase 4 exit still requires a real
capture/MRT semantic equivalence and non-collapse join through the accepted
import/replay consumer. Phase 5 owns CLI import and persistence.
