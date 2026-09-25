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
protocol depth, full-history/out-of-core semantics, cross-platform/live-capture
qualification, representative corpus evidence and measured performance.

## Coverage matrix

| Reference intent | Current state | Gap or qualification |
|---|---|---|
| Offline PCAP/PCAPNG parsing with layered link/network/transport handling | Covered for the implemented container and packet families | PCAPNG archival preservation is broader than semantic decoding of every block, option or secret-related meaning |
| Borrow-first parsing and bounded resource use | Covered in the snapshot path and streaming reader | Streaming windows discard history by contract; logical budgets are not a hard RSS sandbox |
| TCP reconstruction with ordering, duplicates, gaps and conflicts | Covered conservatively with packet provenance and explicit boundaries | No full-history disk-spooled session reconstruction across windows; endpoint-specific TCP behavior is not emulated |
| JSON event/report output and traceable evidence | Covered; streaming output is hash-chained NDJSON and the product has a bounded binary TLV contract | Schema compatibility, versioning and broad cross-language equivalence remain release-review work |
| Registry/profiles and extensible analyzers | Partially covered by trusted in-process detector/plugin traits | No sandbox; no mature feature/profile matrix; plugin output needs a matching trusted replay verifier |
| Common IT protocols | Partial: DNS, HTTP/1 metadata, TLS ClientHello, QUIC invariant metadata, DHCP/DHCPv6, SMB2 header metadata, several network/tunnel decoders and bounded metadata subsets for BGP, SNMP, FTP/TFTP, POP3/IMAP, Telnet, SIP/RTP, PPTP, STP and NetFlow | Most of these additions are framing/envelope metadata only; full service/session semantics and broad conformance remain open |
| Industrial protocols | Partial: DNP3 and Modbus have substantial bounded paths; BACnet/IP, BACnet MS/TP, EtherNet/IP/CIP and constrained IEC 61850 families have bounded metadata or selected fields | Complete services/object models, session/state semantics and normative qualification remain open; unsupported families must stay explicitly unsupported |
| Input sources: files and in-memory streams | Covered | Linux live AF_PACKET capture is not implemented; non-Linux live capture is intentionally out of scope |
| Native Rust library | Covered for the snapshot and streaming crates | Public API stability and a compatibility policy are not yet frozen |
| C ABI for internal consumers | Implemented as an isolated opaque-handle v1 boundary with a real linked consumer harness | Windows MSVC link/execution passes; Linux and other ABI/calling-convention qualification remain open |
| No runtime third-party dependencies | Ordinary runtime paths remain dependency-free | Optional fuzz and oracle tooling have separate development dependencies; this exception must remain explicit |
| Corpus manifest and broad labeled-corpus smoke | A small optional upstream manifest entry plus synthetic fixtures | No representative operational corpus, rights/retention review, or all-family smoke evidence |
| Fuzzing, performance and cross-platform qualification | Harnesses and workflows exist; local Rust/nightly fuzz targets and the independent oracle compile | No sustained fuzz campaign, coverage/crash receipt, benchmark target, or observed Linux/Windows/macOS matrix result |

## What the current implementation adds beyond that baseline

The current opt-in depth addendum now supplies bounded DNP3 object, explicit
Modbus-map, BACnet, CIP, IEC-104, IEC-61850, ISO/COTP/MMS/S7, OPC UA, fieldbus
and IEEE 802.15.4/Zigbee observations, plus source-verified typed history pages.
This closes the gap of having only framing names for those families, but it does
not close full protocol conformance, secure decryption, endpoint-state truth,
timing replay, or complete TCP history. The detailed contract and receipts are
in docs/product/DEPTH_CONTRACT.md.


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

1. Deepen protocol families in a measured order: PCAPNG block semantics,
   BACnet/IP and file-mode MS/TP services, EtherNet/IP/CIP object/session
   semantics, constrained IEC 61850 services, then the highest-value IT
   extensions. Keep metadata-only entries labeled as such.
2. Add protocol-specific known-answer tests from published specifications and
   independent byte builders, including malformed and ambiguous cases.
3. Harden the binary TLV schema and versioning rules with independent
   cross-language fixtures.
4. Extend C-ABI qualification and add Linux live capture only after defining
   ownership, failure, capability checks, shutdown and security boundaries; live
   capture must fail closed when privileges or link assumptions are missing.

### P2 — ergonomics and ecosystem breadth

Add consumer profiles/feature flags, richer registry diagnostics, differential
adapters for external analyzers, and documented API/ABI compatibility tooling.

The next implementation handoff should turn each selected item into an exact
acceptance matrix: protocol and depth, fixture source/hash/rights, independent
oracle, cross-platform commands, benchmark columns, fuzz receipt requirements,
and explicit non-goals. Do not broaden the supported-protocol table merely by
adding names without those witnesses.
