# Additional protocol framing matrix

Current BGP scope, evidence links, and qualification state are maintained in
[`bgp-support-matrix.json`](bgp-support-matrix.json) under the controlling
[BGP completion contract](BGP_COMPLETION.md). The older slice notes below are
historical implementation receipts, not a claim of complete BGP support.

## BGP candidate route-state consumer — additive source candidate

The separate `deep::bgp_state` API is specified in [BGP_STATE.md](BGP_STATE.md). It consumes
normalized captured/imported observations with exact inherited provenance,
source/session/generation/direction isolation, explicit replay and withdrawal
outcomes, conflict alternatives and fail-closed identity quarantine. Candidate
state is not an endpoint RIB, best path, causal proof or authoritative source.
There is no automatic change to existing decoder/event/CLI output, no cross-source
join and no new dependency.

The worker authored 31 native tests; the candidate was then reviewed and passed
the local Windows native product/workspace gates. The accepted review repaired
payload digest computation, missing-direction state mutation and attribute-local
MP bounds. Direct producer budget parity, broader capability/session semantics,
Linux/runtime, live, scale, fuzz and normative qualification remain open.

## DNP3 fragment and streaming confirmation candidates — Windows native acceptance

Accepted root/streaming base: `d9f7c4fbb80c5355643b241fafb9c7687091a1b5`.
The root and streaming implementations maintain separate output seams; neither
changes the generic transaction path. See DNP3 workflow coverage for current
behavior and explicit limits.
The root slice provides `correlate::dnp3_confirmation_candidates`, a reusable
CRC-checked fragment witness verifier, and separate analysis/JSON fields
`dnp3_confirmation_candidates` and `dnp3_confirmation_error`. The streaming
slice adds a separate `dnp3.confirmation_candidate` event projection for
verified TCP fragments, bounded by capture/session/window/generation and exact
participant evidence. It does not replace or change `transaction_candidates`.

One verified CONFIRM and one eligible response fragment in a flow can produce
`candidate_confirmation` only with reversed individual addresses, opposite
captured directions and link DIR, equal fragment sequence and UNS namespace,
CONFIRM CON=0 and response CON=1. Reuse, duplicate confirmations/targets, colliding
header alternatives and unverifiable fragments never select a winner. A
transport-complete fragment need not belong to a complete application message;
this does not decode or complete its object body. Header bytes, source spans,
link CRC dependencies and all packet witnesses remain explicit.

**This worker has not executed Rust.** Cargo, rustc, rustfmt and Clippy were absent
in the Debian Linux worker. Native command attempts are BLOCKED, not PASS. The
38 new Rust tests are authored coverage only. Independent Python checks passed
for 33 fixed link vectors, 15 header-relation cases and an eight-packet capture's
lengths, CRCs, hashes, IPv4/TCP checksums, header offsets and timestamp integers.
Those checks do not execute the Rust verifier, grouping, JSON or CLI. See
[../DNP3_WORKFLOWS.md](../DNP3_WORKFLOWS.md) and the returned validation receipts.

The worker receipt is historical evidence of its unavailable Rust toolchain. The
exact patched worktree has since passed fresh Windows native format, debug/release,
build, warnings-denied Clippy, product, and streaming gates. Linux/macOS runner
receipts remain open and are not inferred from Windows. Secure authentication,
endpoint acceptance/effects, causality and normative conformance are not claimed.
The streaming projection is TCP-only and does not pair separate UDP datagrams;
the generic transaction path remains untouched. Cross-platform CI/runtime
evidence, endpoint-authoritative cross-APDU file-transfer/reconciliation, Group 70 authentication and
secure file semantics, platform/live, scale, fuzz and external-corpus
qualification remain open.

Entries below are **metadata-only source implementations, not native-qualified
full protocol implementations**. Each is independent of external parser
libraries. Sources are in product/src/protocols/; supplemental L2 admission is
in product/src/layer.rs. Runtime recognition can remain ambiguous. A separate,
deeper observer is documented in
[DEPTH_CONTRACT.md](DEPTH_CONTRACT.md) and is opt-in; it does not upgrade these
rows to full protocol support.

The inherited engine provides its own DNP3/Modbus and IT/network capabilities under its existing contracts; this matrix does not relabel or replace them.

The current DNP3 semantic subset covers CRC-validated framing, transport and
application evidence plus direction/PRM/FCB/FCV/DFC link-control fields,
broadcast evidence, named function codes, indexed read selectors,
one/two/four-byte ranges, standard non-secure binary, counter, analog, deadband,
time, packed-status, variable-octet, and control-relay object layouts across
the supported qualifier forms. Group 0 also has a bounded attribute envelope
projection: typed unsigned/signed integer, float-bit-pattern, time, known boolean,
and hash-only string/octet/bit values, plus even-width attribute-list entries;
Group 0 variation 254 read requests remain header-only evidence. Root Group 70
free-format qualifier 0x5B variations 3--8 additionally expose exact
length-prefixed file-object spans, bounded command/status, transport and
descriptor metadata, and hash-only filename/file-specification/authentication-key/
content fields. Reserved secondary
link-control bits and unknown
link functions remain retained frames with explicit diagnostics rather than
being treated as valid semantics. Complete assembled messages receive a second
source-bound semantic report, so an object split across application fragments
can be decoded when the verified bytes are contiguous. The opt-in product depth
sink also correlates complete assembled Group 70 observations into bounded
file-transfer candidates keyed by capture session, endpoint pair, and file
handle, retaining block hashes, gaps, duplicates, conflicts, and witnesses.
It remains intentionally bounded: secure authentication, Group 70 authentication
variation 2, endpoint-authoritative transfer processing, complete endpoint state,
and normative all-variation conformance are not claimed.

| Identifier | Entry surface | Implemented subset | Explicit boundary |
|---|---|---|---|
| netflow9 | UDP | FlowSet/template/options envelopes; template count | No exporter-session template history or full data record decoding |
| bgp | TCP | Common <=4096-byte message envelopes plus opt-in bounded route-evidence normalization for complete OPEN/UPDATE/KEEPALIVE/NOTIFICATION/ROUTE-REFRESH messages, supported prefixes, withdrawals, and path-attribute ranges | No extended-message negotiation, RIB/best-path state, endpoint effect, timing causality, or full path-attribute/conformance semantics |
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
| opcua_tcp | TCP | UA TCP message/chunk header and bounded HEL envelope | The opt-in depth observer adds selected SecurityPolicy#None and Read/Write structures; no secure-channel decryption, certificate trust, or complete service/object model |
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

Unknown or unsupported variants return typed failure or remain opaque; no
insecure or convenient bytes are invented to make a message parse. The opt-in
depth observer now provides a bounded IEEE 802.15.4/Zigbee subset, but security
payloads remain opaque and no key discovery or decryption is performed.
Decryption, secret-key processing, device control and attack attribution are not
implemented. A decoder row or a depth report is not a normative conformance
certificate.
