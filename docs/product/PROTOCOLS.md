# Additional protocol framing matrix

All entries below are **metadata-only source implementations, not native-qualified full protocol implementations**. Each is independent of external parser libraries. Sources are in `product/src/protocols/`; supplemental L2 admission is in `product/src/layer.rs`. Runtime recognition can remain ambiguous.

The inherited engine provides its own DNP3/Modbus and IT/network capabilities under its existing contracts; this matrix does not relabel or replace them.

| Identifier | Entry surface | Implemented subset | Explicit boundary |
|---|---|---|---|
| netflow9 | UDP | FlowSet/template/options envelopes; template count | No exporter-session template history or full data record decoding |
| bgp | TCP | Common <=4096-byte message envelopes, UPDATE length/prefix bounds | No extended-message negotiation, RIB or full path-attribute semantics |
| snmp | UDP | Definite BER message/PDU/varbind framing; version/header metadata | Community/security content not exported; no MIB value interpretation or SNMPv3 decryption |
| ftp | TCP | Bounded command/status line metadata | No credentials, transferred file reconstruction or full multiline state |
| tftp | UDP | RRQ/WRQ/DATA/ACK/ERROR/OACK framing | No negotiated transfer/session reconstruction |
| pop3 | TCP | Command and status line metadata | No authentication/body export or multiline download state |
| imap | TCP | Tagged/untagged line metadata | No literal body or complete IMAP state machine |
| telnet | TCP | IAC command/option envelope | No NVT terminal/session simulation or plaintext export |
| sip | TCP | Start line, bounded headers, explicit Content-Length framing | Folded headers unsupported; no SIP dialog, media or authorization interpretation |
| rtp | UDP | v2 header/CSRC/extension/padding metadata | Structural candidate, not authenticated media or payload decoding |
| pptp | TCP | Control header, length, cookie and message type | Not every message body or GRE/PPP connection state |
| bacnet_ip | UDP | BVLC, NPDU and APDU header envelopes | No complete BACnet services/object model |
| bacnet_mstp | Link type 165, offline | Legacy header/data CRC and frame envelope | No extended frame formats or live serial endpoint |
| enip_cip | TCP | Encapsulation/CPF and common CIP envelope metadata | No CIP object/device semantics, implicit I/O session or full EPATH model |
| goose | EtherType 0x88b8 | Application header and constrained definite-BER fields | Not full IEC 61850 data models or endpoint behavior |
| sampled_values | EtherType 0x88ba | Application header and bounded BER ASDU envelope | Not every ASDU value/time/quality semantics |
| mms | TCP, direct BER subset | MMS BER PDU envelope/invoke metadata | Not full ISO session/presentation/ACSE/COTP or MMS services |
| iec104 | TCP | I/S/U APCI lengths and sequence header metadata | ASDU/service state remains opaque |
| s7 | TCP | TPKT/COTP/S7 header, parameter/data length bounds | No complete fragmented COTP or S7 device semantics |
| hart_ip | TCP | v1 header/type/sequence/length metadata | No complete HART commands, extensions or device state |
| fins_udp | UDP | FINS routing and command header | No full command bodies/device memory model |
| fins_tcp | TCP | FINS TCP envelope and lengths | No full session/routing/device behavior |
| ads | TCP | AMS/TCP and ADS headers | No symbol/object service semantics |
| opcua_tcp | TCP | UA TCP message/chunk header and bounded HEL envelope | No secure channel, decryption, OPC UA service/object model |
| melsec_3e | TCP | Binary 3E request/response header | No ASCII/4E/full PLC command semantics |
| c37118 | TCP | Synchrophasor frame envelope, version and CRC | No complete configuration/data phasor interpretation |
| ethercat | EtherType 0x88a4 | Datagram header/length and working-counter envelope | No process image/device state |
| profinet_rt | EtherType 0x8892 | Constrained cyclic RT identifier/status metadata | No full DCP/acyclic/IRT/device model |
| powerlink | EtherType 0x88ab | Minimal message-type/node envelope | Metadata only; no complete cyclic/control payload validation |
| stp | 802.3 LLC | Config/TCN/RSTP bounded BPDU fields | No MSTP or bridge topology/state simulation |

## Specification references and test scope

See `product/research/catalog.json` for per-family primary specification URLs,
clause references where recorded, independently built fixtures, exact source hashes,
assertions and the normative-review status. A pending standard edition review must
not be converted to reviewed merely because a URL or an upstream implementation
exists. Protocol-specific external semantic adapters and native execution are not
complete for every family. Direct framing fixtures cover 23 stream/datagram subsets;
additional link cases and inherited cases live in the research catalog.

Field ranges refer to the current reconstructed message. Some metadata, such as
counts or derived lengths, is computed from a range rather than a literal single
wire field. Compose message-relative ranges with evidence source spans before
claiming exact packet offsets. Raw state-machine snapshots and fully transitive
provenance for every derived field remain deeper research instrumentation work.

Unknown or unsupported variants return typed failure or remain opaque; no insecure
or convenient bytes are invented to make a message parse. Decryption, secret-key
processing, device control and attack attribution are not implemented. Remaining
families such as Zigbee are unsupported rather than advertised as decoder stubs.
