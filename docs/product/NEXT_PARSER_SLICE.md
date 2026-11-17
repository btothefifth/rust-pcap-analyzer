# Modbus/TCP parser profile

The core parser decodes the following functions from offline MBAP-framed
captures. The root report, streaming message events and single-direction
history reader use the same PDU grammar and field projections.

| Functions | Observed fields |
| --- | --- |
| 1–6, 15, 16 | Addresses, quantities, packed bits, register words and write echoes |
| 20, 21 | Ordered file subrecords, lengths, references and register data |
| 22, 23, 24 | Register masks, separate read/write ranges and FIFO words |
| 43/14 | Access category, conformity level, continuation ID and ordered object spans |

The wire sources are [Modbus Application Protocol V1.1b3, §6](https://www.modbus.org/file/secure/modbusprotocolspecification.pdf)
and the [TCP Messaging Implementation Guide V1.0b, §3.1.3](https://www.modbus.org/file/secure/messagingimplementationguide.pdf).
Addresses are zero-based. The [field and transaction contract](../semantics/CONTRACT.md)
describes pairing, source references and standalone responses. An exception
records a response. Captures alone cannot establish execution on a device.
Serial functions 7/8/11/12/17, RTU, CANopen MEI 13, vendor maps and device
identification across pages remain outside this profile.

## Project intent and current structure

The project turns offline capture bytes into inspectable evidence. Source hashes,
record offsets, packet spans, exact timestamps, transport generations, uncertain
boundaries and resource limits must survive every derived interpretation.

| Owner | Current responsibility | Relevant continuation work |
| --- | --- | --- |
| `src/capture*`, `wire`, `fragment`, `tcp`, `provenance` | Capture containers, packet decoding, reconstruction and exact source witnesses | Preserve the existing transport and evidence contracts |
| `src/modbus.rs`, `src/semantics/modbus.rs`, `src/correlate.rs` | MBAP framing, typed PDUs, field projection and candidate pairing | Preserve source-bound transaction evidence |
| `streaming/src/plugin.rs`, `protocols.rs` | Bounded streaming analyzers, per-window events and correlation | Consume typed parsed results with explicit role context |
| `product/src/protocols`, `product/src/deep` | Broader metadata parsers and opt-in deeper semantics | Reuse core Modbus semantics and retain per-field source spans |
| `history`, `history-app`, `deep::continuation` | Retained TCP generations, indexed replay and application continuation across pages | Page-invariant Modbus output and bounded buffer work |
| `product/src/deep/bgp*` | Capture/MRT/BMP parsing, persisted replay, state, policy and comparison | Continue its existing qualification backlog separately |
| `tools/research`, `tools/product`, `tools/desktop`, `desktop/web` | Comparison, bounded storage/jobs and evidence presentation | Show supported fields, alternatives and uncertainty through current schemas |
| `product/ffi`, `product/live` | C interoperability and optional acquisition | Preserve the existing exported contracts |

### Protocol coverage and sequencing

This is a planning inventory of current owners and meaningful gaps. The broad
registry and opt-in depth implementations have different coverage. Tests and
source determine each claimed subset. A listed family still needs an
edition-specific acceptance contract before promotion.

| Family | Existing implementation | Next depth boundary |
| --- | --- | --- |
| Modbus/TCP | Functions 1–6, 15–16, 20–24 and 43/14, exceptions and request-bound read mappings | Independent normative qualification and vendor-specific interpretation |
| Modbus/RTU | Roadmap scope, outside current TCP parser | Serial framing, CRC, timing provenance and transport adapter |
| DNP3 | Link/transport/application assembly, many objects, confirmations and Group 70 file candidates | Remaining object/qualifier coverage, secure semantics and independent qualification |
| BGP, MRT, BMP | Substantial parsers, sessions, sealed stores, route candidates, query/policy/export and comparison | Public IPv6 RIB and missing-OPEN evidence, additional semantic parity and caller-clocked restart assessment |
| BACnet/IP, MS/TP | BVLC/NPDU/APDU and MS/TP CRC framing, selected BACnet/IP deep services/values and segmentation | Declared confirmed-service/object-property coverage and transaction lifecycle |
| EtherNet/IP/CIP | Encapsulation/CPF, EPATH and selected services, attributed I/O bindings | Negotiated connection lifecycle and explicit object/service coverage |
| MMS/ISO, S7 | BER, COTP continuation, constrained presentation/MMS and S7 fields | Association/context negotiation and specified application services |
| IEC-104 | APCI, selected ASDUs and bounded session observations | Full declared information-object and sequence/session profile |
| GOOSE, Sampled Values | BER/application fields and selected dataset/value observations | Configuration-bound dataset types, quality and sequence semantics |
| OPC UA | TCP/chunks, selected SecurityPolicy None structures and Read/Write fields | Type/namespace/service coverage and secure-channel contracts |
| HART-IP, FINS UDP/TCP, ADS, MELSEC | Headers, command envelopes and selected fields | Separate command schemas and response compatibility per family |
| C37.118 synchrophasor | Framing/CRC and frame type, version, ID and timestamp header fields in `protocols::industrial::phasor` | Configuration and data decoding, configuration-version-bound values and timing/quality semantics |
| EtherCAT, PROFINET RT, POWERLINK | Link envelopes and bounded deep fields | Configuration-bound process data and acyclic services |
| IEEE 802.15.4/Zigbee | Opt-in bounded MAC/NWK/APS/ZCL fields | Fragmentation, cluster coverage and security-context contracts |
| STP | Config/TCN/RSTP fields plus bounded MSTP configuration/CIST fields and MSTI records in `deep::fieldbus` | Edition-specific qualification and topology evidence |
| DNS, DHCP/DHCPv6 | Streaming message/header/options subsets | Record/option coverage and scoped transaction semantics |
| HTTP/1, TLS, QUIC, SMB2 | HTTP headers, TLS hello/record metadata, QUIC public headers and SMB2 headers | Separate message/session profiles with encrypted content availability explicit |
| SNMP | BER/PDU/varbind structure | Typed value coverage and scoped request/security context |
| FTP, POP3, IMAP, Telnet | Bounded control/command envelopes | Multiline/literal/negotiation state with privacy-aware fields |
| TFTP | Opcode/message framing | Negotiated transfer, block rollover and duplicate handling |
| SIP, RTP, PPTP | Signaling/header/control subsets | Dialog, stream and control-session-specific semantics |
| NetFlow v9 | Template/FlowSet envelopes | Exporter-generation template cache and typed records |
| IPFIX | Roadmap scope adjacent to NetFlow | Its own framing, template and enterprise-field contract |

After Modbus, prioritize BACnet confirmed services, CIP connections and
ISO association/application services in separate slices. Keep BGP and DNP3
qualification work visible while these parser families advance. Reorder a
later slice when actual use, independent fixtures or a reproduced defect makes
another family more valuable.

## Continuation measurements

In a local debug build with Rust 1.85.1, one call to `Parser::feed` consumed
16, 32 or 64 coalesced 14-byte mask-write ADUs. A temporary counter at the
old buffer's tail slice recorded 1,680, 6,944 and 28,224 copied tail bytes.
Each surviving tail had one source span. That required 15, 31 and 63 span
copies and two nonempty vector allocations per tail. Discarding the consumed
prefix after each batch brought all three tail counts to zero. Feeding one
byte at a time also copied zero tail bytes in both versions. The test checks
packet offsets and compares the complete sequences of serialized-report hashes.

Elapsed time including report serialization for coalesced input was 13, 25 and
46 ms before and 13, 22 and 44 ms after in this run. The largest input was 896
bytes. Use these measurements to assess copying in this fixture. Process-wide
allocation totals and representative capture throughput remain unmeasured.
