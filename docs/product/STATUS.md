# Product implementation boundary and continuation

This document describes the additive source in `product/`, `tools/product/`,
`tools/research/`, `tools/desktop/` and `desktop/web/`. It does not supersede the
root parser or streaming reconstruction contract. Version: candidate 0.2.0.

## Implementation and qualification are separate

| Surface | Implemented behavior | Qualification / remaining work |
|---|---|---|
| Product Rust API/CLI | Existing independent engine plus metadata decoder adapters and supplemental link-layer observations; fixed local-file CLI, exact spans, bounded output, explicit profiles | Root, streaming, product and FFI format/test/build/clippy checks pass locally on the pinned toolchain; native product worker is not yet qualified through the desktop HTTP path |
| Extra protocols | 30 additional bounded framing/envelope metadata subsets; field ranges; malformed-input errors; no hidden decryption or object/device emulation | See `PROTOCOLS.md`; no blanket full-protocol or full conformance claim |
| In-process extensions | Reuses the streaming detector/analyzer/correlator interfaces and keeps every structural match | Trusted native code; no plugin sandbox; semantic and CPU safety not guaranteed for arbitrary third-party plugins |
| Typed binary TLV | New canonical scalar/container types and length/hash-chained records, Rust writer and Python reader/writer | Python round trips, malformed input and golden scalar tests executed; Rust equivalence not executed |
| Source archive | Chunked, exact source retention, index/part/full hashes, streaming verification and replay | Python tests executed; no large-disk failure campaign or cryptographic authentication |
| Disk stream intervals | Caller-scoped SQLite source intervals, conflicts, first/last/reject policies, bounded reconstruction pieces, source-span hashes | Tested vertical slice; caller must supply justified scope and unwrapped sequence positions |
| Full automatic history | Existing bounded streaming remains unchanged | NOT IMPLEMENTED: automatic disk-backed TCP generation/reassembly and complete protocol state across all window boundaries |
| Desktop workbench | Real local HTTP backend; isolated analysis workers; SQLite queries, paging/virtualization, capture/flow/protocol/transaction/issue views, hex/provenance, cases and research export | Python/HTTP/process/model tests pass (157 Python tests and 11 UI model tests); Windows worker state publication and diagnostics are hardened; native Rust worker is not yet qualified through the desktop HTTP path; offline renderer is separate from HTTP |
| Native desktop packaging | No parser dependencies added to the UI | NOT IMPLEMENTED: Tauri shell, MSI/NSIS/deb/AppImage, signing and installation tests |
| Research comparator | Source-anchored fields, ordered alternatives, missing coverage, evidence-state differences, first observed divergence, no voting | Python tests executed. Earliest-within-coverage is weaker than proving the true earliest endpoint-state divergence |
| Catalog | 68 subjects, 136 independently constructed case records, refs/properties/fuzz/adapter ledger | Registration and artifact maintenance validated. Normative edition review and executed all-family qualification remain BLOCKED |
| Research adapters | Independent container reference; native event normalization; fixed-field TShark adapter; explicit local binaries; attributed receipts | Product/TShark adapters not run natively. They normalize selected fields, not every protocol or every state transition |
| Other external tools | Original comparison harnesses included for attributed Zeek/Suricata/oracle collection | Collection is not comprehensive semantic normalization. No Arkime/libpcap session adapter implemented here |
| Reduction | First-divergence fingerprint-preserving packet-subset reducer with final recheck, frame map and bounded calls | Synthetic predicate tests executed; no new external vulnerability or malformed-container repair claimed |
| Adjudication bundle | Exact research capture, interpretations, diff, specification references, raw tool artifacts and independent packet witnesses | Python end-to-end export/verification tests executed. Integrity does not certify truth or authorship |
| C ABI | Isolated opaque numeric handles; pointer/length contract; create/feed/analyze/copy/destroy; panic boundary; failure state | Rust FFI tests, format, clippy and release build pass; C client source was not compiled or linked because this Windows host has no C compiler |
| Linux capture | Separate explicit opt-in AF_PACKET C executable with Ethernet checks, kernel receive timestamps, output bounds, signal shutdown and drop counters | Linux compilation, injected denial, actual NIC capture and Rust live-stream integration are NOT VALIDATED on this Windows host; the C compiler gate is blocked |
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

Extend DNP3 objects/qualifiers and Modbus/device semantics only through the shared
provenance API. BACnet services, CIP object paths, full MMS presentation/COTP,
GOOSE/SV object semantics and Tier B state machines remain incomplete. Zigbee and
other unimplemented families must remain unsupported, not registry names presented
as decoded support. No secure authentication or encrypted-session decryption is
provided here.

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
