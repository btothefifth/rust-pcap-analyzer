# PCAP Platform Completion Roadmap

## BGP candidate route-state consumer — additive source candidate

The separate `deep::bgp_state` API is specified in [BGP_STATE.md](BGP_STATE.md). It consumes
normalized captured/imported observations with exact inherited provenance,
source/session/generation/direction isolation, explicit replay and withdrawal
outcomes, conflict alternatives and fail-closed identity quarantine. Candidate
state is not an endpoint RIB, best path, causal proof or authoritative source.
There is no automatic change to existing decoder/event/CLI output, no cross-source
join and no new dependency.

The candidate route-state API consumes normalized, source-bound observations
and preserves source/session/generation/direction partitions. Its current
behavior and limits are summarized in the product validation and BGP contracts.

## DNP3 fragment and streaming confirmation candidates — Windows native acceptance

Accepted root/streaming base: `d9f7c4fbb80c5355643b241fafb9c7687091a1b5`.
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

The native implementation, tests, and qualification boundary are documented in
[DNP3 workflow coverage](../DNP3_WORKFLOWS.md) and the product validation plan.
All confirmation rows are candidates, not proof of device receipt, acceptance,
effect, causality, or normative conformance. The streaming projection is TCP-only
and does not pair separate UDP datagrams. Cross-platform, live, scale, fuzz,
external-corpus, secure-authentication, and complete object-profile qualification
remain separate gates.

The completed bounded slices add Group 0 attribute-envelope evidence and Group 70
free-format file-object metadata/content-hash evidence to the root semantic
decoder while preserving hash-only handling for opaque payloads and source-bound
spans. The opt-in depth sink now adds conservative cross-APDU file-transfer
candidate reconciliation with explicit gaps, conflicts, duplicates, and
witnesses. The next priority is endpoint-authoritative transfer semantics or
secure/authenticated semantics; each remains separately gated and must not be
inferred from candidate source coverage.

Status: active project plan  
Owner: repository integration and review  
Execution: bounded implementation slices with isolated integration and local acceptance

## Purpose

This roadmap records the implementation order for evolving the repository into
a thoroughly tested offline PCAP analysis platform. The repository and its
tests are authoritative. Every change must be isolated, validated, reviewed,
documented, and accepted before integration.

The first priority is complete declared **non-secure offline DNP3** support.
The word “complete” is intentionally bounded: it covers the protocol semantics
that can be derived from captured bytes without secrets, device emulation,
active traffic generation, or attack attribution. Secure authentication and
encrypted payload recovery remain explicit later capabilities rather than
implicit promises.

Correctness is not defined by agreement with an existing analyzer. A separate
first-class objective of this platform is to discover, explain, and regress
disagreements between this implementation and other analyzers while preserving
an independently justified result. External dissectors and frameworks may be
used as comparison inputs, corpus sources, or bug-discovery aids, but they are
never normative oracles and their output is never copied into production
behavior without an independent wire-level or specification-based justification.

## Current baseline

The repository already provides PCAP/PCAPNG parsing, packet decoding, TCP
reconstruction, evidence-oriented output, a bounded semantic/deep observer,
history/journal experiments, DNP3 and Modbus framing, multiple protocol
subsets, a desktop/native path, and local Windows validation matrices. The
current limitations and already-accepted behavior are recorded in:

- [`STATUS.md`](STATUS.md)
- [`FOLLOWUP_STATUS.md`](FOLLOWUP_STATUS.md)
- [`PROTOCOLS.md`](PROTOCOLS.md)
- [`DEPTH_CONTRACT.md`](DEPTH_CONTRACT.md)
- [`VALIDATION.md`](VALIDATION.md)
- [`IMPLEMENTATION_HANDOFF.md`](IMPLEMENTATION_HANDOFF.md)
- [`../implementation/CURRENT.md`](../implementation/CURRENT.md)

Every worker packet must name the exact base commit and the controlling
documents it used. Older handoffs are context, not permission to claim that an
open gate has passed.

## Latest verified DNP3 progress

The current local vertical slice extends the root source-bound semantic path
with named application function codes, decoded primary/secondary link-control
bits (direction, PRM, FCB/FCV/DFC, function names and broadcast evidence),
one/two/four-byte point ranges, indexed selectors, analog deadband variations,
unsigned-integer objects, variable-length octet identity, and message-level
decoding across complete assembled application fragments. It also exposes
explicit function labels in the root report. The accepted root slice is now
extended by a TCP streaming `dnp3.confirmation_candidate` projection that
reuses verified fragment witnesses without changing generic transaction
events. It keeps one capture/session/window/generation scope, carries exact
participant evidence, and marks gaps/conflicts or ambiguous stream context
non-candidate. UDP datagrams never pair across datagrams. The overall slice is
still bounded: secure authentication, Group 70 authentication variation 2,
endpoint-authoritative file-transfer semantics, endpoint state, and normative
all-variation conformance remain open.
The next DNP3 job should target the next independent application/object or
reconciliation seam with the same explicit review of recent integrations.

The first post-DNP3 protocol slice is BGP route evidence. It must remain a
coherent evidence package: complete message boundaries, capability-scoped ASN
width, UPDATE prefixes and withdrawals, supported path attributes, unknown
attribute retention, generation separation, malformed/segmented tests, and
explicit non-claims for RIB state, best-path choice, timing, endpoint effects,
and cross-source correlation.

## Ordered implementation program

### Phase DNP3 — first and highest priority

Deliver a vertical slice at a time, keeping each slice independently useful
and reviewable.

1. **Link and transport semantics**
   - source/destination, direction, PRM, FCB/FCV, DFC, broadcast, and
     multi-drop semantics;
   - transport segmentation, interleaving, sequence rollover, retransmission
     and duplicate handling, out-of-order and late segments, tuple/generation
     separation, and exact packet witnesses;
   - explicit distinctions between incomplete, reordered, duplicate,
     conflicting, and unrecoverable evidence.

2. **Application control workflows**
   - all declared non-secure function-code families;
   - confirms, unsolicited responses, class and event scans, time/date
     operations, select/operate/direct-operate/cold-warm-restart style control
     flows where the bytes support a safe evidence interpretation;
   - request/response correlation and per-outstation state without pretending
     to know state that the capture does not prove.

3. **Object and qualifier semantics**
   - complete supported group/variation catalog for binary, double-bit,
     counter, frozen-counter, analog, output, time, and file/control families;
   - all supported qualifier forms, point indexes/ranges, count/range bounds,
     flags, quality, status, timestamps, and per-object spans;
   - cross-fragment object completion and explicit unsupported/ambiguous
     reporting instead of opaque bytes or guessed values.

4. **Conformance evidence**
   - valid captures plus malformed, truncated, contradictory, reordered,
     duplicated, conflicting, rollover, unsolicited, and multi-outstation
     cases;
   - independent expected results, not only self-generated fixtures;
   - real-capture redaction/provenance, fuzz and regression seeds, and
     differential comparison where a reference parser is available; reference
     dissectors are comparison inputs, never correctness or conformance oracles;
   - documentation that states the supported edition/subset and every
     intentional non-goal.

### Phase protocols — after DNP3’s non-secure gate

Complete each family as a coherent semantic package, not merely by adding a
port number or a framing label. BGP is the next protocol priority after the
DNP3 non-secure/reconciliation gate. The order is:

1. BGP: complete OPEN, KEEPALIVE, NOTIFICATION, UPDATE, path-attribute,
   capability, session, stream-reassembly, and malformed/segmented semantics;
   retain conservative boundaries for route state, timing, and external
   routing effects.
2. Modbus/TCP and Modbus/RTU: complete function/data semantics, exception
   responses, transaction correlation, serial timing/turnaround evidence, and
   malformed/segmented cases.
3. BACnet/IP and BACnet MS/TP: APDU/object/property semantics, segmentation,
   invoke correlation, confirmed services, and bounded device identity.
4. EtherNet/IP/CIP: encapsulation/session context, connected/unconnected
   messaging, service/path decoding, and industrial object evidence.
5. IEC 61850 family: MMS/ISO, GOOSE, and Sampled Values with their distinct
   timing, sequence, dataset, quality, and replay semantics.
6. IEC-104, then MMS/ISO/S7: sequence windows, cause-of-transmission,
   information objects, transport/session boundaries, and application
   correlation.
7. OPC UA: secure/non-secure endpoint identity, message/chunk boundaries,
   namespace/type information, and an explicit boundary for decryption and
   certificate validation.
8. HART-IP, FINS, ADS, MELSEC, EtherCAT, PROFINET, POWERLINK, Zigbee, and
   STP: promote each from a bounded framing subset only when semantic cases,
   independent oracles, and evidence limits exist.
9. Remaining IT/network families: HTTP, DNS, DHCP, SNMP, FTP, TFTP, POP3, IMAP,
   Telnet, TLS metadata, SIP, RTP, PPTP, NetFlow/IPFIX, with protocol-specific
   correlation and timing rather than one generic parser path.

Each protocol package must update `PROTOCOLS.md`, product status, API/CLI
documentation, fixtures, and the validation matrix. “Supported” means the
documented semantic contract and tests pass; metadata-only framing remains
explicitly labeled as partial.

### Phase history and replay fidelity

Finish the disk-backed TCP endpoint-history system and make replay/timing
claims precise:

- generations and tuple reuse, sequence-number wraps, retransmissions,
  overlaps, conflicts, missing handshakes, asymmetric captures, timestamp
  reversal, and late evidence;
- separate packet order, capture time, stream order, generation hypotheses,
  unknown, incomplete, and conflict states;
- crash-safe checkpoints, restart/replay, corrupt-journal rejection, schema
  migration/versioning, quotas, cancellation, bounded memory, and exact packet
  witnesses;
- tests for common replay bugs and timing bugs: duplicate delivery, overlap
  choice, delayed ACK interpretation, retransmission timing, clock reversal,
  out-of-order capture, tuple reuse, and packet loss;
- independent replay reports and a first-divergence register against reference
  adapters where a comparison is meaningful.

### Phase evidence, research, and storage

- **Independent correctness and comparison program**
  - maintain protocol-specific semantic contracts, independent expected values,
    and adversarial fixtures before comparing another implementation;
  - record each disagreement with exact packet spans, parser versions/config,
    raw comparison output, the applicable wire/specification reasoning, and a
    classification such as our defect, comparator defect, ambiguous evidence,
    unsupported scope, or unresolved investigation;
  - turn confirmed disagreements into minimized regression cases and publish
    coverage-aware reports that distinguish parser correctness, timing/replay
    behavior, performance, and unsupported features;
  - measure common failure classes directly, including TCP replay and stream
    generation, sequence/overlap choice, timestamp ordering, retransmission,
    fragmentation, malformed input, resource exhaustion, and protocol-specific
    state correlation;
  - keep comparison adapters replaceable and version-pinned so results remain
    reproducible even when an external framework changes.
- typed versioned evidence schemas and NDJSON/TLV equivalence;
- large-archive indexing, interval queries, provenance, corruption recovery,
  migration, concurrency, and disk-budget qualification;
- parser-state witnesses and source/tool/config identity;
- TShark, Zeek, Suricata, Arkime, and libpcap adapters where their output is
  a useful independent comparison, with tool availability recorded instead of
  silently skipped;
- reproducible bundles, real operational corpus coverage, normative review,
  and coverage-aware reporting of unknowns.

### Phase desktop, FFI, and capture

- complete browser-to-native workbench behavior with accessibility, large
  result virtualization, cancellation, error states, provenance/hex views,
  native file selection, and no silent fallback;
- packaging, signing, install/upgrade/rollback, and a documented recovery
  path;
- cross-platform C ABI qualification for invalid handles, nulls, limits,
  destroy/reuse, concurrency, panic isolation, calling conventions, and
  ownership;
- actual Linux AF_PACKET capture qualification for permissions, drops,
  timestamps, shutdown, and Rust integration. Windows-only proof is not
  presented as Linux proof.

### Phase performance, fuzzing, and release qualification

- sustained stateful fuzzing of framing, reassembly, history, and semantic
  decoders;
- realistic corpus and 50–500 GiB measurements for throughput, RSS, disk,
  index build, and query latency;
- security review of untrusted PCAP handling, resource limits, archive
  extraction, and output paths;
- reproducible receipts, release checks, and a qualification report that
  separates code, focused tests, integration, scale, platform, normative,
  and observed-behavior status.

## Implementation and acceptance workflow

Changes are intentionally bounded to one vertical slice or a small set of
mechanically inseparable edits. Work pauses at a milestone boundary, a
meaningful product decision, repeated validation failure, missing external
evidence, or a safety-sensitive ambiguity. Continue only when the remaining
work is already specified by this roadmap and the repository contracts.

For every change:

1. work from a committed or otherwise verified snapshot with selected context
   and secret/binary filtering;
2. isolate proposed changes from the protected integration branch;
3. validate changed paths, patch scope, sizes, and supporting evidence;
4. run format, build, tests, Clippy, focused protocol checks, and relevant
   documentation checks;
5. review semantics, scope, error paths, resource/concurrency behavior,
   security boundaries, and proof quality;
6. repair straightforward integration issues or record substantial gaps;
7. update this roadmap and the controlling product/current-state docs;
8. merge only reviewed, verified changes and verify the published revision.

External changes are untrusted input. Never include credentials, cookies,
private keys, production data, or arbitrary writable repository access in
review packages. Reject archive traversal, absolute paths, escaping symlinks,
`.git` replacement, unexpected binaries, secrets, and oversized content.

## Definition of done

The platform is complete only when the repository has a documented semantic
contract for each claimed protocol, the corresponding independent evidence and
tests pass, replay/timing behavior is qualified, the desktop/FFI/capture
boundaries are honest, scale/fuzz/security gates have receipts, and the final
Rust/CLI/native matrices pass on every claimed platform. Until then, status
must continue to distinguish implemented behavior from open qualification.
