# Product implementation boundary and continuation

## Current BGP program

The controlling current plan is [BGP_COMPLETION.md](BGP_COMPLETION.md), and the
machine-checked current capability inventory is
[`bgp-support-matrix.json`](bgp-support-matrix.json). The BGP sections below are
retained as chronological slice receipts. Where their old "still open" wording
conflicts with the matrix or accepted code/tests, the matrix and completion
contract govern and the leaf document must be reconciled when touched. No local
PASS implies Linux, sustained fuzz, real-corpus, scale, endpoint, or normative
qualification.

## Captured BGP producer parity — source candidate

The captured producer extension in [BGP_PRODUCER.md](BGP_PRODUCER.md) stages
`decode_pcap` state until complete budget and output checks succeed. It binds
source/session/capture context, retains both OPEN directions and repeated
advertisements, exposes exact capability and path-attribute occurrences, and
uses the first ordinary path-attribute occurrence as the only semantic candidate
(subject to its own validation) while retaining later occurrences with explicit
discard dispositions. Repeated
MP_REACH_NLRI or MP_UNREACH_NLRI requires session reset. Repeated OPENs
no longer infer a new generation. A missing session produces unknown generation,
not another session's state. Negotiation and all authority claims remain false.

Imported normalizer bytes and import/state/replay partition, clock, checkpoint
and boundary contracts remain unchanged. The new occurrence value coordinates
are validated by state admission and excluded from state/association path
identity, while their evidence is retained. Captured output gains additive fields;
strict consumers and event hashes must account for the documented migration.

The worker did not execute Rust, but the integrator applied the direct patch in
an isolated Windows checkout and repaired one default-depth compatibility issue
and six Clippy test-fixture issues before acceptance. Fresh format, workspace
check/test/Clippy, product release test/Clippy, producer/replay/import/state/
association vectors, root validation and portable product validation all pass.
Linux/macOS runtime, live, scale, fuzz, secure, external-source verification,
adapter and normative qualification remain open. Review findings and exact
remaining boundaries are recorded in the producer contract and validation
receipt.

## Generic normalized BGP replay — source candidate

The opt-in `deep::bgp_replay` API in [BGP_REPLAY.md](BGP_REPLAY.md) wraps existing contextual
imported observations in a bounded, ordered feed envelope. It reuses source,
batch/checkpoint, clock and generation metadata; exact replay is a no-op,
changed ordered records quarantine the feed, and boundaries remain explicit.
Pages are staged through the existing candidate reducer before receipt publication.

Replay and association receipts preserve provenance and coverage. Partial or
unknown feed coverage cannot be upgraded by a final marker or caller association
context. External-source verification and the caller's adapter remain outside
this I/O-free module. There is no new CLI/event integration, dependency, endpoint
RIB, best-path, reachability, attack, causality or source-authority claim.

The original worker did not run Rust. The integrated replay slice has since
passed its focused native and independent-vector gates on Windows, including
atomic accounting. Those receipts remain local-platform evidence only; the
broader qualification dimensions in the current BGP matrix stay open.

## Generic BGP evidence association — local Windows native acceptance

The separate `deep::bgp_association` API is specified in
[BGP_ASSOCIATION.md](BGP_ASSOCIATION.md). It relates normalized BGP route
evidence to caller-adapted internal flow/security evidence under an explicit
namespace, dimension and clock policy. It retains alternatives, conflicts,
provenance and unresolved coverage without selecting a best path or inferring
reachability, causality or source authority. It does not ingest external feeds,
change existing capture/CLI/event output or add dependencies. The complete
candidate passes the local Windows native/portable gates; Linux/macOS, live,
scale, fuzz, security and normative qualification remain open.

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

This document describes the additive source in `product/`, `tools/product/`,
`tools/research/`, `tools/desktop/` and `desktop/web/`. It does not supersede the
root parser or streaming reconstruction contract. Version: candidate 0.2.0.

## Implementation and qualification are separate

| Surface | Implemented behavior | Qualification / remaining work |
|---|---|---|
| Product Rust API/CLI | Existing independent engine plus metadata decoder adapters and supplemental link-layer observations; fixed local-file CLI, exact spans, bounded output, explicit profiles | Root, streaming, product and FFI format/test/build/clippy checks pass locally on the pinned toolchain; the direct browser smoke path reaches the native product worker with source binding, while full desktop qualification remains open |
| Streaming DNP3 confirmation projection | Separate TCP-only `dnp3.confirmation_candidate` events and typed participant records built from verified DNP3 fragments; capture/session/window/generation scope, exact evidence, conservative gap/conflict handling | Focused unit, contract and semantic-pipeline coverage passes locally; no UDP cross-datagram pairing, causality/receipt claim, endpoint-authoritative file-transfer result, or Linux/macOS native receipt yet |
| Root DNP3 Group 0 attributes and Group 70 file objects | Group 0 bounded source-bound attribute envelopes plus Group 70 qualifier 0x5B free-format variations 3--8 with exact command/status/transport/descriptor fields and hash-only filename, file-specification, authentication-key, and content values | Focused semantic coverage and full local gates pass on Windows; the opt-in depth sink now adds bounded candidate reconciliation, while Group 70 authentication variation 2, endpoint-authoritative transfer semantics, secure/authenticated meaning, vendor semantics, and full normative variation coverage remain open |
| BGP route evidence and association | Opt-in depth normalization for complete captured messages with generation-scoped OPEN context, bounded OPEN/NOTIFICATION/ROUTE-REFRESH metadata, IPv4/selected multiprotocol prefixes, withdrawals, supported path attributes, unknown-attribute hashes, exact ranges, a generic imported-observation shape, and a separate bounded association seam for caller-adapted internal flow/security evidence | Focused unit, real pcap-depth regression and local Windows association gates pass; no external-feed adapter, extended-message negotiation, complete path-attribute/RIB semantics, best-path state, endpoint effect, timing causality, production sink, cross-platform/live/scale/fuzz/security or normative qualification |
| Extra protocols | 30 additional bounded framing/envelope metadata subsets; field ranges; malformed-input errors; no hidden decryption or object/device emulation | See PROTOCOLS.md; no blanket full-protocol or full conformance claim |
| Protocol-depth observer | Opt-in pcap-evidence-product::deep reports for DNP3 objects, mapped Modbus registers, BACnet, CIP, IEC-104, IEC-61850, ISO/COTP/MMS/S7, OPC UA TCP, EtherCAT/PROFINET/POWERLINK/STP and IEEE 802.15.4/Zigbee; all are bounded and source-bound | Ten direct depth contract tests, DNP3 reconciler unit cases, product all-target tests and real pcap-depth smoke pass. Each family remains partial; no full protocol, secure decryption, endpoint-effect or normative claim |
| Stateful depth consumers | pcap-depth analyze adds verified packet-map observations; history-app pages sealed history through typed evidence ranges and preserves state across pages while cutting on gaps/conflicts | Smoke-tested on shipped OPC UA and history fixtures. Complete endpoint history, timing replay and large-scale qualification remain open |
| Optional OPC UA transform | Python-only, explicitly authorized Basic256Sha256 signed-body verification with optional AES provider boundary | Three boundary tests pass; no key discovery, certificate validation, endpoint identity, or automatic Rust decryption |
| In-process extensions | Reuses the streaming detector/analyzer/correlator interfaces and keeps every structural match | Trusted native code; no plugin sandbox; semantic and CPU safety not guaranteed for arbitrary third-party plugins |
| Typed binary TLV | New canonical scalar/container types and length/hash-chained records, Rust writer and Python reader/writer | Python round trips, malformed input and golden scalar tests executed; Rust equivalence not executed |
| Source archive | Chunked, exact source retention, index/part/full hashes, streaming verification and replay | Python tests executed; no large-disk failure campaign or cryptographic authentication |
| Disk stream intervals | Caller-scoped SQLite source intervals, conflicts, first/last/reject policies, bounded reconstruction pieces, source-span hashes | Tested vertical slice; caller must supply justified scope and unwrapped sequence positions |
| Full automatic history | Existing bounded streaming remains unchanged; the new history application consumes sealed, source-verified ranges and preserves state across its pages | NOT IMPLEMENTED: a complete automatic disk-backed TCP endpoint-history state machine, arbitrary replay timing, and complete protocol state across all windows |
| Desktop workbench | Real local HTTP backend; isolated analysis workers; SQLite queries, paging/virtualization, capture/flow/protocol/transaction/issue views, hex/provenance, cases and research export | Python/HTTP/process/model tests pass (191 Python tests and 11 UI model tests); the direct browser-to-native smoke gate passes with real requests and source binding; packaging, accessibility and broad desktop qualification remain open; offline renderer is separate from HTTP |
| Native desktop packaging | No parser dependencies added to the UI | NOT IMPLEMENTED: Tauri shell, MSI/NSIS/deb/AppImage, signing and installation tests |
| Research comparator | Source-anchored fields, ordered alternatives, missing coverage, evidence-state differences, first observed divergence, no voting | Python tests executed. Earliest-within-coverage is weaker than proving the true earliest endpoint-state divergence |
| Catalog | 68 subjects, 136 independently constructed case records, refs/properties/fuzz/adapter ledger | Registration and artifact maintenance validated. Normative edition review and executed all-family qualification remain BLOCKED |
| Research adapters | Independent container reference; native event normalization; fixed-field TShark adapter; explicit local binaries; attributed receipts | Product/TShark adapters not run natively. They normalize selected fields, not every protocol or every state transition |
| Other external tools | Original comparison harnesses included for attributed Zeek/Suricata/oracle collection | Collection is not comprehensive semantic normalization. No Arkime/libpcap session adapter implemented here |
| Reduction | First-divergence fingerprint-preserving packet-subset reducer with final recheck, frame map and bounded calls | Synthetic predicate tests executed; no new external vulnerability or malformed-container repair claimed |
| Adjudication bundle | Exact research capture, interpretations, diff, specification references, raw tool artifacts and independent packet witnesses | Python end-to-end export/verification tests executed. Integrity does not certify truth or authorship |
| C ABI | Isolated opaque numeric handles; pointer/length contract; create/feed/analyze/copy/destroy; panic boundary; failure state | Rust FFI tests, format, clippy, release build and the real linked C consumer harness pass under the prepared Windows MSVC environment; other ABI/OS combinations remain open |
| Linux capture | Separate explicit opt-in AF_PACKET C executable with Ethernet checks, kernel receive timestamps, output bounds, signal shutdown and drop counters | Linux compilation, injected denial, actual NIC capture and Rust live-stream integration are NOT VALIDATED on this Windows host; the Windows C compiler/link gate now passes |
| Performance/fuzz | Existing tools plus new research target and feature-matrix commands | No sustained campaign, no 50–500 GB benchmark, no guaranteed RSS or throughput |

## Highest-priority integration gates

1. Complete the native desktop-worker path. The repository-wide native format,
   debug/release, feature-matrix, build and warnings-denied checks pass on the
   declared toolchain. Confirm product event counts, packet-to-field span
   propagation and simultaneous detector handling through the actual worker path.
   Do not downgrade root/streaming code.
2. The 23 catalog direct-payload cases have been exercised through the compiled
   `product/examples/research_probe.rs` binary. Add capture-driven adapters for
   inherited/network/link/state subjects where a direct payload probe is
   insufficient. Validate each support label against actual decoded fields and
   protocol-specific valid-neighbor/malformed tests.
3. Exercise `scripts/gui_smoke.py` against the compiled Rust engine in a normal
   Windows and Ubuntu browser environment. The current host has not established
   browser-to-native qualification. Do not weaken browser security to obtain a
   pass.
4. Install or use a supported C toolchain in a separate validation environment,
   then compile, link and run the C harness with the native FFI library. Test
   wrong handles, one-shot errors, output caps, concurrent calls, and platform
   calling conventions.
5. Review the schema fixtures, catalog specification editions and normative
   assertions. A generic truncation/mutation test is not a conformance suite.

## Concrete next vertical slices

### Automatic full-history TCP, without changing evidence ownership

Add an independent disk-backed packet-to-transport journal from the Rust engine,
then persist TCP generation decisions, SYN/FIN/RST observations, unwrapped sequence
anchors and conflict alternatives. The existing Python interval store is not that
state machine. Use strict source/version/config identities and crash-safe checkpoints.

Acceptance needs interleaved flows, tuple reuse, delayed old packets, more than one
sequence wrap, timestamp reversals, missing handshakes, conflicts arriving after
flush, quota exhaustion, restart, partial/corrupt journals and exact source replay.
A repeated source hash and retained payload alone must not claim session truth.
Compare each supported result with a bounded snapshot where both modes have the
same evidence and policy; document where finite budgets still prevent completion.

### Research-state instrumentation

Emit parser/reassembler transition witnesses with before/after state identities,
input ranges, explicit policy decisions, layer dependencies and implementation
version. Preserve alternate interpretations separately. Current research imports
can carry values and witnesses, but the engine does not yet emit a complete state
snapshot at every supported semantic boundary.

For each layer add independently built conformance, malformed-neighbor and ambiguity
families; make adapters normalize the same source-anchored fields without erasing
ordering or coverage gaps. Missing earlier coverage must prevent claims of having
located the globally earliest divergence. Regressions need specification review,
not automatic agreement with TShark or with this engine.

### Industrial depth and unsupported families

The root semantic path now decodes a broader bounded non-secure DNP3 object and
qualifier subset, including named function codes, indexed read selectors,
1/2/4-byte ranges, deadband and variable-octet evidence, CROB control evidence,
primary/secondary link-control fields and broadcast evidence, and a second
source-bound semantic pass over complete assembled messages;
the opt-in depth observer additionally covers bounded DNP3 objects/qualifiers, explicit
Modbus maps, BACnet services, CIP object paths, selected MMS presentation/COTP,
GOOSE/SV structures, IEC-104 state observations, and IEEE 802.15.4/Zigbee
framing. These are still incomplete subsets with explicit unsupported notes.
Zigbee security payloads and all secure/encrypted session decryption remain
unsupported. Expand each family only with independent valid/malformed/ambiguous
fixtures and source-bound evidence.

### Desktop hardening and packaging

Keep query/worker ownership while optionally adding a native shell later. The
current Python backend is intentionally runnable without npm/Tauri dependencies.
Add native file selection, installed runtime distribution, OS signing, native
accessibility review, secure upgrades and actual platform cancellation tests as a
separate delivery. Bound expensive overview/timeline work and benchmark realistic
workspace sizes before claiming billion-row interactive performance.

## Release decision

This is an implementation source handoff, not a certified or production-ready
release. C/Linux, browser-to-native, full-history, scale, fuzz and normative
qualification gaps prevent that designation. Do not replace BLOCKED/NOT VALIDATED
with PASS based on Python tests, Rust compilation alone, source hashes, code
inventory, static UI screenshots, or configured CI definitions.
