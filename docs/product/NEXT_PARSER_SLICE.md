# Next parser slice — Modbus/TCP

Proposed implementation outline, based on main
`afc5d6d8423e8bf153ff03788dda555c803a9af5` after PRs #2 and #3 merged.
The implementation stages below are pending. This document supplies the proposed
scope, ownership, compatibility rules and acceptance criteria for a later PR.

## Recommendation

Complete the device-agnostic Modbus/TCP parser across the existing evidence
pipeline. Consolidate its overlapping PDU validation and field decoding, extend
its declared public-function coverage, and expose request-bound interpretation
only when the existing correlation rules establish a unique compatible pair.

Modbus already spans core, streaming, deep observation and history replay. Its
bounded message size and accessible protocol specification make it a practical
next step toward first-class protocol support. BGP has substantially deeper
state and persistence coverage following the merged work. DNP3's remaining
secure and endpoint-dependent semantics require their own contracts. The audit's
parser and desktop defects belong to the separate bug-fix PR.

## Project intent and current structure

The project turns offline capture bytes into inspectable evidence. Source hashes,
record offsets, packet spans, exact timestamps, transport generations, uncertain
boundaries and resource limits must survive every derived interpretation.

| Owner | Current responsibility | Relevant continuation work |
| --- | --- | --- |
| `src/capture*`, `wire`, `fragment`, `tcp`, `provenance` | Capture containers, packet decoding, reconstruction and exact source witnesses | Preserve the existing transport and evidence contracts |
| `src/modbus.rs`, `src/semantics/modbus.rs`, `src/correlate.rs` | Modbus framing, common-function fields and conservative transaction candidates | One PDU owner, richer fields and shared pair compatibility |
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
| Modbus/TCP | MBAP, functions 1–6/15/16, exceptions, fields and candidate pairing | Shared typed PDU owner and the scope below |
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

## First-class parser acceptance

For each promoted protocol profile, require a named edition and function/service
set, typed parse results, exact field spans, explicit unknown/malformed/incomplete
outcomes, bounded state and work, normal entrypoint integration, and independent
positive and negative witnesses. Stateful meaning must carry its context and
provenance. A detector, port registration or generic envelope supplies only its
specific evidence. Keep unsupported extensions recoverable as bounded raw spans
or hashes under the current privacy policy.

## Modbus scope

Use Modbus Application Protocol V1.1b3 and the TCP messaging implementation guide
V1.0b as the wire authorities. Review the exact clauses while writing the function
vectors and record those citations beside the independently derived expectations.
The application specification defines the existing common functions, file-record
functions 20/21, mask write 22, read/write 23, FIFO 24, and device identification
43/14. It identifies 7/8/11/12/17 as serial-only. CANopen 43/13 requires an
additional specification. [Application specification](https://www.modbus.org/file/secure/modbusprotocolspecification.pdf),
[TCP messaging guide](https://www.modbus.org/file/secure/messagingimplementationguide.pdf)

| Stage | Function scope | Required output |
| --- | --- | --- |
| A | Existing 1–6, 15, 16 and their exceptions | Shared validation and equivalent field/role/error behavior |
| B | 22, 23, 24 | Typed masks, read/write ranges, register values and FIFO counts |
| C | 20, 21 | Ordered subrequests/subresponses, file/record references, lengths and values |
| D | 43/14 | Read category, conformity, continuation metadata and ordered object IDs/value spans |

All stages retain MBAP identity, original function code, role and source spans.
Unknown functions, reserved forms, serial-only functions and CANopen remain
explicitly outside this profile. RTU transport, vendor register maps, scaling,
TLS recovery and device execution are later scopes. Device-identification pages
remain individual observed pages until a separately specified, source-bound
assembly can establish a complete enumeration.

## Ownership and compatibility

1. Introduce one typed PDU decoder below existing public APIs in `src/modbus.rs`.
   If the added function families obscure that owner, use `src/modbus/pdu.rs`
   and `src/modbus/transaction.rs`, with `src/modbus.rs` retaining the public
   entrypoints. Keep transport framing separate from role-specific PDU meaning.
2. Represent parsed function variants, exception responses and opaque extensions
   with closed enums and borrowed spans. Keep explicit request and response
   interpretations when the role is unknown. Validate once per interpretation
   and project both shape and semantic fields from that result.
3. Adapt `src/semantics/modbus.rs`, `response_matches`, `check_pair`, streaming
   `emit_modbus` and deep continuation to that owner. Retain public callable
   signatures and existing fields/error dispositions where their contracts fit.
   Enumerate every caller before removing duplicate validators.
4. Keep source-bound field projection distinct from request-derived enrichment.
   A response's register bytes and a request's starting address have different
   witnesses. Derived coil/address fields must identify both participants.
5. Extend the existing root and streaming correlation owners. Preserve their
   bounded capture/session/window/generation and direction partitions. Replace
   duplicated function compatibility logic with shared typed summaries at their
   existing adapter seam. Keep any required public string-token compatibility
   wrapper at the edge until its real callers migrate together.
6. Use existing Report, evidence, JSON/TLV and limit owners. New fields must pass
   their byte/field/record admission before emission. If a serialized semantic
   contract changes incompatibly, version its producer and every real consumer
   together and retain the declared legacy reader behavior. Keep this slice within the existing crates, storage contracts and parser APIs.

### Transaction interpretation

Matching uses the existing conservative candidate model within the complete
selected analysis scope. Bind the key to capture/session, transport generation,
unit ID, transaction ID, function and opposite directions. Wire addresses stay
zero-based. Explicit configured role context may select a role. Ambiguous role
context preserves alternatives.

| Observed group | Disposition |
| --- | --- |
| One valid request and one compatible opposite-direction response with verified boundaries | Candidate pair with separate request and response witnesses |
| One valid unique compatible pair with an unverified start boundary | Preserve `candidate_unverified_boundary`. Request-derived fields carry that conditional status and both source witnesses |
| Reused transaction identifier, multiple eligible requests/responses or conflicting directions | Ambiguous group with every bounded alternative retained |
| Response alone or incomplete observation window | Orphan/incomplete evidence and independently decoded response fields |
| Unique pair with incompatible echo, quantity, padding or function-specific shape | Inconsistent pair with the disagreeing fields identified |
| Unknown function or unresolved role | Opaque/alternative interpretation with unavailable pair-derived fields |
| Gap, conflict or generation change | End the affected eligibility scope, retain the reason and preserve unrelated scopes |

For a unique compatible pair, enrich read registers with requested addresses and
read bits with the requested count and padding check. Preserve the pair's
boundary status on every derived projection. An unverified-boundary candidate
retains conditional enrichment, while standalone response fields retain their
original evidence. Compare the same request/response bytes with and without
verified start boundaries through root and streaming output, asserting status,
field availability and both witnesses. Extended functions use
function-specific compatibility including echoes, record order, counts and
requested object/category evidence. An exception remains a response observation.
Retain the supported exception compatibility contract.

Evaluate enrichment only after the owning bounded group is complete, so later
identifier reuse cannot leave a previously emitted unique interpretation in the
final result. Use existing group finalization where available. Any incremental
output that precedes that point must carry its provisional status through the
current terminal event contract.

History application replay currently consumes one direction and one protocol
hypothesis. It receives the shared standalone parser and preserves unresolved
roles. Cross-direction pairing across history queries and arbitrary time-based
expiry are separate work. Query page boundaries alone never end a partial ADU.

## Efficiency and limits

A Modbus/TCP ADU has a small fixed wire maximum. The scaling concerns are the
number of messages, evidence spans, simultaneous candidate groups and output
records. Retain existing configured caps and validate aggregate intermediate
state as well as output. Give a limited parse an explicit terminal disposition.
A limit failure must preserve emitted evidence and leave continuation in the
existing documented retry/cut state.

`deep::reassembly::StreamBuffer::take` currently copies the remaining tail for
each consumed frame. First measure copied bytes, span traversals, allocations
and terminal latency through `Parser::feed` for many coalesced small Modbus ADUs
and one-byte fragmented input. The optimization target is linear byte/span work
in admitted input plus emitted provenance. Prefer a cursor with bounded
compaction or a single batch drain using the existing evidence representation.
Preserve the public buffer contract and the other continuation protocols.

Use fixed small inputs at three sizes, fixed segmentation and explicit message,
span, input and output budgets. A proposed initial fixture ceiling is 8 MiB of
source and 64 MiB of output per run, with a 60-second operation timeout and one
worker. Measure cold and warm runs separately on the same toolchain/hardware.
Keep exact output/spans equal before comparing costs. Record deterministic copy
and visit counters alongside latency, and reject superlinear growth in those
counters for the admitted shapes. Process RSS remains a separate measurement.

Before builds or replay, measure checkout, tooling and scratch occupancy. Keep
aggregate project storage strictly below 50,000,000,000 bytes and stop growing
at 40 GB. Reuse the checkout and caches. This slice needs only small synthetic
fixtures and minimized independent samples.

## Maintainability and documentation

Consolidate the duplicated Modbus semantics before adding functions. Split modules
only where the new boundary has a clear owner and simplifies actual callers.
Keep the BGP store/replay modules cohesive unless evidence identifies a separate
change there.

Replace compressed expressions in touched adapters with named intermediate
values and readable control flow. Remove comments that repeat the operation,
unnecessary wrappers and copy-pasted status paragraphs. Preserve explanations
of provenance, ambiguity, units and limits where they govern behavior.

Use `docs/implementation/CURRENT.md` for current navigation and one capability
inventory for supported protocol subsets. Update protocol navigation in
`docs/PROTOCOL_MATRIX.md` and reconcile Modbus coverage in
`docs/product/PROTOCOLS.md` and the research catalog against code and tests. Mark dated handoffs as historical and link them from
current guidance. Keep local execution, hosted checks, normative review and
scale evidence in their existing distinct receipt fields.

## Implementation sequence and proof

Each stage below is pending and should be reviewable independently. The final
feature requires the whole agreed scope to pass its caller-facing tests.

1. Freeze the supported function/role table and existing API/event behavior.
   Independently construct minimal valid, malformed, truncated and boundary
   vectors from the cited clauses. Capture current results before refactoring.
2. Consolidate existing common functions with equivalent output and source spans.
   Prove root decode/report, streaming events, opt-in deep output and history
   replay using the same small source bytes. Retain distinct scope labels where
   entrypoints have different context.
3. Implement stages B–D through the same parser and adapters. For every function,
   cover request, success, exception, inconsistent response, exact/one-over count,
   every truncation boundary and unsupported neighbors. Keep opaque extensions.
4. Add request-bound projection at existing finalized correlation boundaries.
   Exercise duplicate/reused IDs, interleaved units, opposite and same directions,
   gap/conflict cuts, missing handshake, orphan responses and query pagination.
   Verify useful standalone fields survive unavailable pairing context.
5. Measure and repair continuation copying if the bounded baseline confirms the
   repeated-work concern. Prove segmentation invariance, equal field provenance,
   limit/cut behavior and all other continuation protocols after the change.
6. Update current coverage and examples from executed results. Run format,
   warnings-denied Clippy, debug/release tests, feature-profile checks and normal
   CLI/JSON/TLV/history integration through the existing validation commands.
   Run a bounded fuzz smoke with retained minimized failures where the installed
   toolchain supports it. Record unavailable campaign evidence explicitly.
7. Apply the review-loop skill until two successive full reviews by distinct
   fresh agents find no remaining actionable feedback on unchanged code, tests
   and implementation contracts. Publish the implemented feature separately.

Acceptance requires independent expected field values and failure dispositions,
exact packet spans, preserved existing supported behavior and a real capture-to-
consumer witness for each entrypoint. External parser agreement is comparison
input requiring adjudication. The audit and this outline supply a starting point
for that implementation and its qualification.
