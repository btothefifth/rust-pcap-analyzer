# Protocol-depth and history contract

## BGP candidate route-state consumer — additive source candidate

The separate `deep::bgp_state` API is specified in [BGP_STATE.md](BGP_STATE.md). It consumes
normalized captured/imported observations with exact inherited provenance,
source/session/generation/direction isolation, explicit replay and withdrawal
outcomes, conflict alternatives and fail-closed identity quarantine. Candidate
state is not an endpoint RIB, best path, causal proof or authoritative source.
There is no automatic change to existing decoder/event/CLI output, no cross-source
join and no new dependency.

This is a historical route-state acceptance receipt, not current validation.
That review repaired payload digest computation, missing-direction state
mutation and attribute-local MP bounds. Later producer work also added direct
budget/state staging and RFC 7606 duplicate dispositions. Broader
capability/session semantics and Linux/runtime, live, scale, fuzz and normative
qualification remain open; see the current implementation pointer for the
latest local validation evidence.

## DNP3 workflow candidate — native gates run locally

The additive worker slice based on
`fcbfddbf5565b25e46d9849aef39698c47713bbc` is specified in
[../DNP3_WORKFLOWS.md](../DNP3_WORKFLOWS.md). It preserves the reviewed root layouts
and adds bounded link admissibility, source-bound confirm/unsolicited/class/event/
time observations, stricter witness-verified candidate pairing, duplicate/conflict
boundaries, rejected-link ranges, and incomplete-safe root/streaming/deep projections.
Root complete-message object completion is retained; bounded Group 0 attribute
envelopes and root Group 70 free-format file-object variations 3--8 are now
supported as exact, hash-safe evidence; bounded opt-in multi-APDU candidate
reconciliation is now available, while endpoint-authoritative completion, Group 70
authentication variation 2 and secure semantics remain open. A separate
TCP-only streaming confirmation projection is now integrated on top of verified
fragment witnesses; generic transactions and UDP datagram boundaries remain
unchanged.

The worker environment lacked Rust and returned only reference-vector/package
receipts; those receipts are not native proof. This isolated Windows integration
has now passed fresh root format/build/test/clippy, product debug/release and
feature-matrix gates, streaming debug/release and clippy gates, and the focused
DNP3 workflow suites. Those results validate this candidate slice, not complete
protocol or release qualification. Full platform/live, scale, fuzz, external
corpus, secure and normative gates remain open. The next smallest semantic slice
is an independent DNP3 endpoint-authoritative file-transfer/reconciliation or secure-semantics
package with an explicit review of the recent Group 70 integration, streaming
integration, and other relevant implemented pieces.

This document is the controlling contract for the additive protocol-depth
implementation introduced after the product baseline. It extends
[IMPLEMENTATION_HANDOFF.md](IMPLEMENTATION_HANDOFF.md); it does not replace the
core capture, streaming, provenance, or history contracts.

The depth layer is a bounded observer of captured bytes. It is not an endpoint
emulator, a packet repairer, an attack detector, a device controller, or a
normative conformance certificate.

## Entry points and ownership

The default root and streaming commands keep their existing behavior. Depth is
opt-in through these entry points:

| Entry point | Purpose | Source boundary |
| --- | --- | --- |
| pcap-evidence-product::deep | Decode one already-framed protocol unit | The caller supplies the protocol hypothesis and EvidenceBytes; no port-only identity is inferred |
| pcap-depth decode | Inspect a standalone protocol unit | The input is explicitly not a PCAP; the report says so and binds only to the supplied unit hash |
| pcap-depth analyze | Add depth observations to the existing event stream | ProductSink re-reads packet bytes from the capture and PacketMap verifies their hashes before retaining witnesses |
| pcap-evidence-history-app | Apply stateful application framing to a sealed history range | History::evidence_range verifies journal/index/source identity and returns candidate bytes or explicit gaps/conflicts |
| tools.depth.opcua_crypto | Optional authorized OPC UA symmetric transform | Python-only tool boundary; the Rust parser never discovers keys or decrypts automatically |

The product CLI’s ordinary command remains the established product path. The
new pcap-depth binary does not silently replace it or fall back to a weaker
mode.

## Shared evidence rules

Every report carries:

- the exact EvidenceBytes used by the decoder;
- message-relative field ranges, rather than invented packet offsets;
- a support label of implemented-partial for this layer;
- explicit status notes for unsupported, incomplete, ambiguous, rejected, and
  limited conditions;
- device_effect_established=false and normative_conformance_certified=false.

The implementation never chooses bytes from a conflict because they are
convenient. A missing or contradictory transport range is a boundary. A page
boundary in a verified history range is not a transport boundary.

The default limits are 1 MiB per unit, 4,096 fields, 1,024 elements, depth 16,
4,096 evidence spans, 128 active states, 16 MiB retained evidence, 8 MiB work,
and 8 MiB encoded output. Callers may lower them, but a zero or excessive value
is rejected. Limits are logical safety budgets, not a claim about process RSS.

## Implemented protocol subsets

These are intentionally partial, source-bound subsets. Implemented means the
listed structures are validated and emitted by the current code; it does not
mean the protocol family is complete.

| Family | Current depth | Explicitly not claimed |
| --- | --- | --- |
| DNP3 | Root semantic reports plus the opt-in depth observer provide bounded non-secure link/application evidence, including direction, PRM, FCB/FCV/DFC, broadcast, named function codes, application object groups/variations, indexed qualifiers, 1/2/4-byte ranges, CROB/control evidence, time/deadband/variable-octet fields, file metadata, and secure-authentication rejection; complete assembled messages, exact per-fragment object witnesses, and bounded Group 70 file-transfer candidate reconciliation are available to the depth sink | Complete object database semantics, endpoint-authoritative file-transfer/session completion, secure authentication, endpoint state, or normative all-variation conformance |
| BGP | The opt-in depth observer normalizes complete captured BGP messages into source-bound route evidence with generation-scoped OPEN capability context, bounded OPEN/NOTIFICATION/ROUTE-REFRESH metadata, IPv4 and selected multiprotocol prefixes, withdrawals, supported path attributes, unknown-attribute hashes, and exact ranges; caller-supplied imported observations can use the same schema with an explicit non-wire-verified source kind | Extended-message negotiation, full path-attribute replacement semantics, RIB/best-path state, endpoint effects, timing causality, cross-source correlation, or normative conformance |
| Modbus | Raw register evidence plus caller-supplied register/device maps with explicit word/byte order and rational scaling | Device state, write success, or physical process state without an external matched request and operator-supplied map |
| BACnet/IP | BVLC/NPDU/APDU framing, bounded BER/application/context tags, selected Who-Is/I-Am/property fields, and bounded segmented sessions | Complete object/property model, MS/TP live serial behavior, or device effects |
| EtherNet/IP/CIP | Encapsulation/CPF, bounded EPATH, common service/status fields, Forward Open shapes, and explicit I/O binding objects | Complete CIP object model, implicit-I/O truth, secure authentication, or inferred connection state |
| IEC 60870-5-104 | I/S/U APCI, selected ASDU information-object shapes/times, and sequence/session observations | Complete command semantics, endpoint state, or proof that a control changed a process |
| IEC 61850 | Bounded GOOSE and sampled-value headers/BER structures with count and range checks | Full SCL/data model, authenticated endpoint behavior, or every ASDU value/quality variant |
| ISO/COTP, MMS, S7 | TPKT/COTP boundaries, bounded session/presentation BER, selected MMS data, and selected S7 variable operations | Full OSI session/ACSE/presentation state or complete MMS/S7 device semantics |
| OPC UA TCP | HEL/ACK/ERR, OPN/MSG/CLO framing, explicit SecurityPolicy#None handling, and selected Read/Write service bodies | Secure-channel decryption, certificate trust, endpoint identity, complete service model, or inferred application state |
| EtherCAT, PROFINET RT/DCP, POWERLINK, STP | Bounded datagram/BPDU/control metadata and selected ranges | Process-image/device state, complete cyclic/acyclic models, or topology simulation |
| IEEE 802.15.4/Zigbee | Optional FCS validation, MAC/NWK/APS framing, and selected ZCL foundation values | Security-header decryption, key discovery, plaintext recovery, or complete Zigbee application semantics |

Existing product framing rows in PROTOCOLS.md remain valid as a separate
surface. This table describes the deeper observer and must not be read as a
blanket full-support claim.

## Stateful continuation and replay boundaries

deep::continuation::Parser accepts arbitrary verified history pages for the
supported stream protocols. It retains application state across ordinary page
boundaries and emits a completed report only after a validated frame boundary.

The following events cut state explicitly:

- a noncontiguous range, conflict, or ambiguous placement;
- a sequence/token/fragment discontinuity;
- an explicit caller cut;
- the selected range ending while application state is pending.

The cut report retains discarded state evidence and marks the result incomplete.
It does not pretend the preceding or following page is contiguous. Duplicate
segments are observed without appending them; conflicting duplicates poison the
scope until the caller cuts it. This is the intended conservative behavior for
TCP replay bugs, retransmission ambiguity, timing/order anomalies, and history
page boundaries.

The history application consumer emits a hash-chained NDJSON sequence:
analysis.start, zero or more message/boundary events, optional incomplete or
aborted evidence, and analysis.complete. A complete event means that the
selected verified range was consumed; it never means complete endpoint history.
The output is no-clobber and uses a partial file until the final hard-link
publication succeeds.

No timing model is invented. Captured timestamps remain source evidence; this
layer does not sleep, replay traffic, reorder packets by wall clock, or claim
that a reconstructed order is the endpoint’s actual order.

## Optional authorized OPC UA transform

tools/depth/opcua_crypto.py is deliberately outside the Rust parser trust root.
It accepts only caller-supplied, already-derived keys and an explicit
authorized=True call. It supports the Basic256Sha256 symmetric Sign path and
the optional AES-CBC SignAndEncrypt path only when the caller has installed the
declared cryptography provider. It verifies the MAC before examining padding
or returning derived bytes.

The receipt records the source chunk hash, derived-body hash, key reference,
direction, sequence/request scope, and the fact that certificate trust,
endpoint identity, source-capture verification, and key export were not proved.
No key material or plaintext is placed in the receipt. The tool does not perform
key discovery, OPN asymmetric decryption, certificate validation, or secret
retention.

## Validation status for this integration

The following evidence was executed on the pinned Windows Rust toolchain before
publication:

- product compile, format, warnings-denied Clippy, and all-target tests;
- ten direct depth-contract tests, DNP3 and BGP pcap-depth CLI regressions,
  focused DNP3 and BGP unit cases, and the existing product test suites;
- history and history-app compile/check/Clippy/tests;
- a real pcap-depth analyze smoke run against the shipped OPC UA PCAP,
  producing events.ndjson, packets.map, and receipt.json;
- a real history build, generation query, and history-app run against the
  shipped history fixture;
- three Python tests for explicit authorization, signed-body verification, and
  tamper rejection in the optional transform.

The following remain open and are not implied by these passes:

- full protocol conformance or complete application state for any listed family;
- Linux live capture and actual NIC evidence;
- sustained fuzz campaigns and large-capture/RSS/throughput qualification;
- representative external-capture replay;
- normative edition review, secure-channel decryption qualification, and
  certificate/endpoint identity validation;
- a complete TCP endpoint emulator or bug-free replay claim.

The next smallest valuable slices are independent protocol-specific valid/
malformed/ambiguous fixture families, full-history stress cases for tuple reuse,
wraps, late conflicts and timestamp reversals, and a measured source-bound
performance matrix. Each must update this contract and its receipt rather than
upgrading a support label implicitly.
