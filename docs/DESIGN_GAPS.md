# Reference design comparison and remaining gaps

This is a public-safe comparison against the supplied layered parser-library
design baseline. The private design document, private repository names and
third-party capture collections are not copied into this repository. This file
is a gap register, not a second controlling implementation contract.

## Bottom line

The current repository is already stronger than the reference in evidence
provenance, conservative reconstruction, explicit uncertainty, source-bound
indexes, no-clobber output and bounded streaming event delivery. It is not yet
a complete general-purpose protocol framework. The biggest differences are
protocol breadth, full-history/out-of-core semantics, binary/FFI interfaces,
Linux live capture, representative corpus evidence and measured performance.

## Coverage matrix

| Reference intent | Current state | Gap or qualification |
|---|---|---|
| Offline PCAP/PCAPNG parsing with layered link/network/transport handling | Covered for the implemented container and packet families | PCAPNG archival preservation is broader than semantic decoding of every block, option or secret-related meaning |
| Borrow-first parsing and bounded resource use | Covered in the snapshot path and streaming reader | Streaming windows discard history by contract; logical budgets are not a hard RSS sandbox |
| TCP reconstruction with ordering, duplicates, gaps and conflicts | Covered conservatively with packet provenance and explicit boundaries | No full-history disk-spooled session reconstruction across windows; endpoint-specific TCP behavior is not emulated |
| JSON event/report output and traceable evidence | Covered; streaming output is hash-chained NDJSON | No binary TLV output contract yet; schema compatibility and versioning remain release-review work |
| Registry/profiles and extensible analyzers | Partially covered by trusted in-process detector/plugin traits | No sandbox; no mature feature/profile matrix; plugin output needs a matching trusted replay verifier |
| Common IT protocols | Partial: DNS, HTTP/1 metadata, TLS ClientHello, QUIC invariant metadata, DHCP/DHCPv6, SMB2 header metadata and several network/tunnel decoders | Many protocols remain absent or shallow, including BGP, SNMP, FTP/TFTP, POP3/IMAP, Telnet, SIP/RTP, PPTP, STP and NetFlow |
| Industrial protocols | Partial: DNP3 and Modbus have substantial bounded paths | BACnet, EtherNet/IP/CIP and constrained IEC 61850 are not implemented; other industrial families are not even stubs |
| Input sources: files and in-memory streams | Covered | Linux live AF_PACKET capture is not implemented; non-Linux live capture is intentionally out of scope |
| Native Rust library | Covered for the snapshot and streaming crates | Public API stability and a compatibility policy are not yet frozen |
| C ABI for internal consumers | Not implemented | Add only if an actual consumer and ownership/ABI contract justify it |
| No runtime third-party dependencies | Ordinary runtime paths remain dependency-free | Optional fuzz and oracle tooling have separate development dependencies; this exception must remain explicit |
| Corpus manifest and broad labeled-corpus smoke | A small optional upstream manifest entry plus synthetic fixtures | No representative operational corpus, rights/retention review, or all-family smoke evidence |
| Fuzzing, performance and cross-platform qualification | Harnesses and workflows exist; local manifests compile | No sustained fuzz campaign, coverage/crash receipt, benchmark target, or observed Linux/Windows/macOS CI result |

## What the current implementation adds beyond that baseline

- Packet-to-byte-span provenance through capture, fragment, stream and protocol
  evidence, including explicit gaps and conflicting alternatives.
- Exact timestamp treatment, source hashes, event hash chains and source-bound
  SQLite projections with semantic replay verification.
- Conservative TCP generation handling and transaction correlation that refuses
  to turn labels into attack or success truth.
- No-clobber publication and process-boundary tooling for reproducible local
  analysis.
- A documented bounded-window model that makes discarded history and incomplete
  protocol coverage visible instead of implying unlimited completeness.

## Prioritized follow-up

### P0 — close before making broad correctness or scale claims

1. Freeze the public event/schema compatibility policy and add schema fixtures
   that prove deterministic JSON, hash-chain replay and unknown-event handling.
2. Define a full-history mode, or explicitly keep bounded windows as the only
   promise; if adding disk spooling, specify restart, corruption, late packets,
   deduplication and cross-window session identity before coding.
3. Add a real benchmark matrix for small, many-flow, long-lived TCP, fragments,
   tunnels and high-duplicate captures, recording throughput, peak RSS, output
   amplification, cuts and replay cost.
4. Run POSIX fuzz campaigns for every target, retain duration/coverage/crash
   receipts and promote minimized failures into deterministic tests.
5. Observe the configured CI matrix and add a corpus manifest with provenance,
   licensing, privacy and expected observations; do not treat a URL alone as
   permission to redistribute a capture.

### P1 — expand the framework where users actually need it

1. Implement protocol families in a measured order: PCAPNG block semantics,
   BACnet/IP and file-mode MS/TP, EtherNet/IP/CIP, constrained IEC 61850, then
   the highest-value IT extensions.
2. Add protocol-specific known-answer tests from published specifications and
   independent byte builders, including malformed and ambiguous cases.
3. Add binary TLV only with a canonical field schema and versioning rules.
4. Add a C ABI and Linux live capture only after defining ownership, failure,
   capability checks, shutdown and security boundaries; live capture must fail
   closed when privileges or link assumptions are missing.

### P2 — ergonomics and ecosystem breadth

Add consumer profiles/feature flags, richer registry diagnostics, differential
adapters for external analyzers, and documented API/ABI compatibility tooling.

The next implementation handoff should turn each selected item into an exact
acceptance matrix: protocol and depth, fixture source/hash/rights, independent
oracle, cross-platform commands, benchmark columns, fuzz receipt requirements,
and explicit non-goals. Do not broaden the supported-protocol table merely by
adding names without those witnesses.
