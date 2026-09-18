# Implementation handoff: reconcile the original design with the expanded product

This file is the single handoff package for the next implementing agent. Apply it
to the public `rust-pcap-analyzer` repository. The repository is the product; the
reference parser and the supplied design documents are inputs to reconcile, not a
reason to rename, privatize or narrow the product.

## Mission

Build a trustworthy, generic, offline-first PCAP/PCAPNG analysis product that
retains the original design's disciplined parser boundaries while adding the
research, evidence, history, desktop and interoperability capabilities already
present in this repository.

The result must remain generic and public. Do not add personal names, customer
names, private product codenames, private deployment assumptions, credentials,
vendor secrets or references to the private source documents. Do not copy the
original documents' private identity or their private-distribution assumption into
public source. The explicit public-repository requirement is authoritative for
publication; the original design's technical safety and correctness intent remains
authoritative for implementation quality.

## Authority and non-negotiable boundaries

Treat these as separate contracts, in this order:

1. The current user request and this repository's public API/evidence contracts.
2. The original design's technical intent: bounded, deterministic, inspectable,
   offline-capable parsing with explicit unsupported behavior.
3. The expanded product scope: research comparison, evidence indexing, history,
   desktop workbench, adapters, typed output, FFI and optional live capture.

Never resolve disagreement by silently weakening a safety or evidence boundary.
When an added feature needs broader behavior, put it behind an explicit product
layer, feature, mode or adapter and document its evidence limits.

The following are hard requirements:

- The shipped core remains Rust-first, deterministic, dependency-minimal and
  usable offline. Do not make Python, a browser, a database, a capture daemon or
  an external analyzer a hidden runtime dependency of the core parser.
- Parsing is bounded. Every public entry point needs limits for bytes, records,
  nesting, active flows, buffered payload, output, work and disk. Exhaustion is an
  explicit incomplete/blocked/error result, never silent truncation presented as
  success.
- Preserve exact source identity and provenance. Keep capture hashes, record and
  packet offsets, spans, timestamps as raw/exact values, protocol-layer evidence,
  warnings, unsupported reasons and reconstruction policy in the result.
- Never invent packet, stream, transaction, timestamp, confidence or attack
  semantics. Unknown, missing, ambiguous, conflicting and unsupported are distinct
  states.
- Preserve duplicate and ordered observations in research and differential output.
  Parser disagreement is evidence to investigate, not a vote. Agreement with an
  external tool is not proof of correctness.
- Do not decrypt TLS or other encrypted sessions, retain secrets, emulate devices,
  or claim attack detection/attribution merely because a message was decoded.
- Live capture is explicit opt-in and fail-closed. The offline parser must not
  silently open an interface, inject traffic, call a remote service or fall back
  from a missing native engine to a weaker implementation.
- All generated files are no-clobber unless a caller explicitly chooses a new
  destination. Source and evidence artifacts must be crash-safe and verifiable.
- Keep the public repository free of private identity and private operational
  assumptions.

## Current repository boundary

The current tree has three intentional layers:

| Layer | Owns | Must not absorb |
| --- | --- | --- |
| Core Rust and `streaming/` | PCAP/PCAPNG records, packet layers, bounded TCP observations, evidence schemas, deterministic output and source binding | GUI state, SQLite schema, external-tool truth, automatic full-history claims |
| `product/` and `product/ffi/` | Product protocol observations, typed output, adapters, feature profiles, FFI and explicit live-capture surface | Unbounded parser state, hidden native fallbacks, unsupported-family claims |
| `tools/`, `desktop/`, `desktop/web/` | Research cases, catalogs, comparison, reduction, storage, workbench queries and presentation | Authority to certify parser truth, silent repairs, secret retention, protocol semantics not emitted by the engine |

Maintain dependency direction from the outer layers to the inner layers. A Python
or browser representation must be derived from a source-bound producer artifact;
it must not become a second authority. A UI label must not upgrade `unknown`,
`unsupported`, `blocked` or `incomplete` into `pass`.

## What is already integrated

The current tree provides:

- additive product Rust workspace and product CLI;
- bounded protocol/framing and industrial observations with explicit profiles;
- typed binary records and Python readers/writers;
- source archives, source-bound indexes and disk-backed interval/history pieces;
- research catalog, properties, adapters, comparison, reduction and adjudication
  artifacts;
- a local HTTP workbench, isolated worker processes, SQLite query views, hex and
  provenance views, cases and research export;
- FFI handles and a separate opt-in Linux capture implementation;
- native root/streaming/product/FFI format, debug/release, build, feature-matrix
  and warnings-denied checks, plus 157 Python tests, catalog maintenance and 11
  JavaScript model tests on the current Windows host.

These facts do not establish full protocol conformance, complete TCP history,
linked C ABI execution, Linux capture, browser-to-native qualification, sustained
fuzzing, large-capture performance or normative correctness.

## Required implementation order

### Phase 0: establish a trustworthy baseline

Before changing behavior:

1. Read `docs/implementation/CURRENT.md`, this file, `docs/product/STATUS.md`,
   `docs/product/VALIDATION.md`, the core streaming contract and the public API
   docs.
2. Run the native and portable gates with an explicit toolchain path when needed.
3. Record the first failing boundary and the smallest reproducible fixture. Do not
   replace a blocked gate with a pass or delete a test.
4. Keep unrelated working-tree changes intact and update only the controlling
   contract/current pointer when a design decision changes.

Acceptance: a receipt distinguishes code, focused tests, integration, C header
compile, linked ABI, Linux live failure, actual capture, browser-to-native,
performance, fuzzing and normative review as separate statuses.

### Phase 1: lock the core parser contract

Audit every root and streaming public path for:

- PCAP classic endian/precision variants and PCAPNG section/interface changes;
- short reads, length arithmetic, malformed options, unknown blocks and truncated
  records;
- exact timestamp handling, signed offsets, absent/inexact clocks and numeric
  serialization;
- Ethernet/VLAN/SLL/SLL2/raw/loopback, IPv4/IPv6, extension headers, fragments,
  TCP/UDP and unsupported link/protocol dispositions;
- bounded active flows, memory/disk/output budgets, cancellation, restart and
  explicit window-cut/incomplete evidence;
- deterministic JSON/NDJSON/TLV output and source-bound index/replay behavior.

For every claimed behavior add a valid fixture, a malformed or ambiguous neighbor,
an independent oracle where possible, and a test proving the result retains source
spans and the correct status. Preserve the existing root and streaming contracts;
do not simplify them to make product integration easier.

Acceptance: the root and streaming gates remain green with `--locked --offline`,
and every unsupported or budget-exhausted path has an observable reason and no
false completion event.

### Phase 2: finish product protocol depth without overstating support

Implement protocol families in vertical slices. Each slice must include:

1. A versioned decoder contract and bounded input/output limits.
2. Valid cases, field-boundary cases, truncation cases, contradictory cases and
   neighboring messages that must remain unsupported.
3. Exact packet/stream spans, layer dependencies, warnings and raw bytes where
   interpretation is incomplete.
4. A support label tied to actual decoded fields and executed tests, not a catalog
   registration alone.
5. Independent differential or specification evidence where available, while
   retaining ordered alternatives and coverage gaps.

For industrial protocols, deepen DNP3 object/qualifier semantics, Modbus device
semantics, BACnet services, CIP object paths, MMS presentation/COTP, GOOSE and
sampled-value semantics only through the shared provenance API. Keep secure or
encrypted semantics explicitly unsupported. Do not turn a framing detector into a
full protocol claim.

Acceptance: each family has a bounded conformance subset, malformed-neighbor
tests, a documented unsupported boundary, and a receipt proving which cases were
actually executed.

### Phase 3: implement full-history TCP as a separate state machine

The current bounded streaming reconstruction and the Python interval store are not
complete automatic TCP history. Implement a Rust-owned disk-backed transport journal
without changing the evidence ownership of the core.

Required state and policies:

- connection generations keyed by a sufficiently specific tuple plus SYN/FIN/RST
  and epoch evidence;
- relative sequence anchors and more than one sequence-number wrap;
- retransmission, duplicate, overlap and conflicting-byte policies with retained
  alternatives rather than convenient overwrites;
- missing handshakes, asymmetric captures, timestamp reversal, delayed old
  packets, tuple reuse, out-of-order data, FIN/RST races and late conflicts;
- packet-to-range index, source spans, exact policy/config/engine identities,
  crash-safe checkpoints, restart/replay and corrupt-journal rejection;
- quotas and cancellation that produce incomplete evidence rather than a verified
  partial session.

Do not call retained source bytes or a repeated source hash full history. Compare
bounded and full-history modes only when the evidence and policy are identical.

Acceptance must include deterministic fixtures for interleaving, tuple reuse,
sequence wrap, missing handshake, overlap conflict, late conflict, restart,
partial journal, disk quota, cancellation and changed source. Add a same-source
replay oracle and verify that generated stream bytes have exact packet witnesses.

### Phase 4: make research comparison scientifically useful

Treat the catalog as a maintenance index, not a qualification certificate.

- Keep case IDs, source hashes, input bytes, tool versions, command lines, configs,
  coverage and output hashes together.
- Normalize only fields that the source producer actually emitted. Retain raw
  alternatives, order, duplicates, missing fields and unsupported states.
- Define first divergence only within common coverage. If an earlier layer is
  unknown or uncovered, report earliest observed within coverage, not earliest true
  divergence.
- Separate operational failure, timeout, missing tool, source mismatch and semantic
  disagreement. Never convert an operational failure into a parser result.
- Add protocol-specific adapters incrementally. A generic adapter may compare
  framing/metadata but must not imply application-semantic agreement.
- Preserve raw external artifacts as attributed evidence; do not treat external
  analyzers as an oracle without a reviewed contract.

Acceptance: forged/rehashed reports, reordered arrays, duplicate anchors, missing
coverage and source identity mismatch are rejected or explicitly classified;
comparison export is reproducible and no-clobber.

### Phase 5: harden the desktop workbench and packaging

Keep the workbench optional and local. It may expose history, research and raw
bytes, but each view must show source identity, evidence status and truncation or
coverage boundaries.

- Keep worker ownership, cancellation and stderr/stdout separation explicit.
- Keep atomic state publication safe for Windows readers and writers; use unique
  temporary names and bounded retry rather than partial writes.
- Never let a missing native engine silently select container inspection as native
  analysis; label container-only mode clearly.
- Bound query pages, previews, hex, timeline aggregation, SQLite work and disk
  retention. Close database handles deterministically on Windows.
- Add normal-browser-to-native tests, accessibility checks, package install/
  upgrade/uninstall tests and signing only as separate, evidenced gates.

Acceptance: HTTP/process/model tests are green, worker failures expose a bounded
diagnostic, cancellation leaves no false completion, and browser/package gates
remain blocked rather than claimed when the environment cannot run them.

### Phase 6: complete FFI and live capture safely

The FFI surface must have a C harness compiled and linked on each supported ABI.
Test invalid handles, null/length pairs, one-shot errors, output limits, concurrent
calls, destroy/reuse, panic containment and calling conventions. Keep opaque
handles isolated and never expose internal pointers after ownership ends.

Live capture must remain a separate explicit opt-in executable or feature. Require
interface selection, privileges, bounded receives, timestamps, drop counters,
signal shutdown, output limits and an injected permission-denial test. Prove that
the offline parser cannot open a device accidentally and that live output retains
capture identity and loss/incompleteness evidence.

Acceptance: linked C execution and Linux injected denial pass in a supported
environment; otherwise the receipt stays BLOCKED with the exact missing tool or OS.

### Phase 7: performance, fuzzing and release qualification

Build a measured matrix before making efficiency claims:

- small and large captures, many flows, long-lived flows, tuple reuse, fragments,
  tunnels, duplicates/conflicts, NDJSON/TLV, indexing, archive/replay, malformed
  files and cancellation/restart;
- throughput, peak process-tree RSS, disk high-water mark, output amplification,
  query latency and error rates;
- 50-500 GB qualification only with measured hardware, OS, compiler, flags, input
  hashes and reproducible commands.

Run separate fuzz targets for containers, packet layers, TCP state transitions,
application framing, TLV, research imports and desktop request boundaries. Record
seed/config/toolchain/coverage/time/RSS/artifacts and promote minimized defects to
deterministic regression tests. A generic mutation campaign is not stateful TCP
coverage.

Normative protocol qualification requires reviewed editions/specifications,
traceable assertions, valid and invalid vectors, and an independent reviewer. A
catalog row, parser name or successful compile is not normative qualification.

## Required final handoff from the implementing agent

Return one machine-readable and human-readable summary containing:

1. exact base and resulting commit;
2. files changed and the contract each change implements;
3. commands run, counts and receipt paths;
4. every PASS, BLOCKED, NOT_RUN and NOT_IMPLEMENTED item with evidence;
5. source identities, toolchain and platform;
6. remaining design gaps and the next smallest vertical slice;
7. explicit confirmation that no private identity, secrets, hidden network access
   or silent fallback was added.

Do not claim production-ready, full protocol support, bug-free TCP replay, complete
history, secure, real-time, cross-platform, or efficient at 50-500 GB unless the
corresponding evidence class above is complete. If the implementation cannot
satisfy a requirement in the current environment, keep the code honest, mark the
gate BLOCKED, and hand back the smallest reproducible artifact needed for the next
environment.

## Suggested first prompt to the implementing agent

> Work in the public `rust-pcap-analyzer` repository. Read
> `docs/product/IMPLEMENTATION_HANDOFF.md`, `docs/product/STATUS.md`,
> `docs/product/VALIDATION.md`, `docs/implementation/CURRENT.md`, the core
> streaming contract and the API docs before editing. Treat the original design
> as the technical baseline and the existing product layers as additive scope.
> Preserve the core's offline, bounded, source-bound, fail-closed behavior. First
> run the current validation matrix, then implement only the next vertical slice
> you can prove end to end. Add independent fixtures and malformed/ambiguous
> neighbors, retain unknown/unsupported/conflict states, update the controlling
> contract and current pointer, and return the required evidence summary. Do not
> copy private names or assumptions into the public tree, do not silently fall back
> between analysis modes, and do not claim unsupported protocol, TCP-history,
> browser, FFI, live-capture, scale, fuzz or normative capabilities.
