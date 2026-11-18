# Changelog

## 0.2.0 — root Rust crate

Modbus/TCP message and transaction values now retain their parsed interpretations
and source bindings. Rust callers that previously constructed these values with
struct literals must migrate. Use `ModbusMessage::from_adu` for one complete
frame, `modbus::decode` for a stream, and `correlate::transactions` or
`engine::analyze` to finalize candidate pairs. `ModbusResult::default()` creates
an empty result. Exhaustive `ApplicationData` matches must handle
`ModbusFailed { capture, error }`. Read TCP generation results from
`TcpTracker::finish`; they now include the first uncertain payload witness and the packet IDs
excluded by a subsequently observed SYN in `outside_syn_span`. `wire::Datagram`
carries `declared_payload_len`, the IP payload length after decoded extensions.
For a complete datagram constructed by a caller, use the payload's byte length.
Read finalized snapshot observations through `Analysis::applications()` and transport
generations through `Analysis::flows()`. Read the producing configuration with `Analysis::config()`.
Callers editing observations can use `applications().to_vec()` and pass the
edited list to `correlate::transactions`. If a message’s transaction ID, unit,
or function disagrees with its captured ADU, correlation marks it unclassified
and uses the wire header to identify competing observations.

The root crate is consumed through path dependencies within this repository and is unpublished.
The change affects Rust source compatibility. Captures, the v1 semantic report
and event formats, and the public legacy correlation-token reader retain their
existing formats. See the [Modbus field contract](docs/semantics/CONTRACT.md).

## Unreleased - bounded protocol depth and history consumer, 2026-09-20

Integrated the previously unvalidated depth draft as an opt-in product layer:
bounded DNP3 object, mapped Modbus, BACnet, CIP, IEC-104, IEC-61850, ISO/COTP/
MMS/S7, OPC UA, fieldbus and IEEE 802.15.4/Zigbee observations with explicit
unsupported/security boundaries; a packet-map/deep-event sink; the pcap-depth
CLI; typed source-verified history ranges and the history-app consumer; and an
optional explicitly authorized OPC UA symmetric transform.

Added direct conflict/gap/security/framing tests, warnings-denied Clippy fixes,
real PCAP/history smoke runs and the controlling DEPTH_CONTRACT.md. This does
not claim full protocol conformance, complete TCP replay, timing replay, secure
decryption, endpoint effects, representative-capture coverage, large-scale
performance or normative qualification.

## 0.1.0 — hardening follow-up, 2026-09-18

Added configured-port, datagram-local UDP DNP3 analysis with preserved packet
provenance; IPv6 fragment identity and offset-zero protocol handling; stricter
Modbus common-function shape and response consistency checks; bounded TCP, fragment
and protocol-state fixes; incremental checksum support; optimized provenance
slicing; advisory protocol probes; eight fuzz targets; and an independent synthetic
CLI hardening oracle.

The local Windows evidence now covers 128 executed native tests from 130 selectors,
including 37 focused hardening regressions, plus the 93-case compiled-CLI oracle.
The optional fuzz campaign remains unexecuted because this Windows host has no POSIX
libFuzzer worker and the pinned fuzz dependency is not cached offline. Real-world
captures, cross-platform CI observations, performance qualification, and security
review remain open.

## 0.1.0 — first working local baseline, 2026-09-16

Implemented offline capture readers/writers, exact clocks, packet and stream
reconstruction, DNP3/Modbus framing, provenance, transaction/attempt candidates,
source-verified indexing, JSON CLI and conservative filesystem publication.
Included synthetic fixtures, native tests, independent Python checks, semantic
mutation targets, fuzz harnesses and multi-platform CI configuration.

**Historical baseline validation:** the initial configured Windows gate passed with
Rust 1.85.1 and the native linker. Later hardening evidence is recorded above and
in `docs/VALIDATION.md`; no claims of equivalence to Arkime/Wireshark or success on
an external capture corpus are made.
