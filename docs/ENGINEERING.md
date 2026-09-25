# Controlling engineering contract — v1

This file owns four canonical sections: decision/state, system/criteria, test evidence,
and execution plan. API and format documents explain this contract; they do not
create competing policy. `CURRENT.md` is only navigation. A source artifact is not
native execution, representative replay, a deployment, or an attack verdict.

## 1. Decision and state kernel

### Outcome and authority

Produce an offline Rust library and CLI that can expose where packet-to-session-to-
protocol interpretation diverges, with every reconstructed byte traceable to source
packet bytes. The baseline deliverable was a local repository ZIP. For this task, the
user explicitly authorizes publishing this synthetic source tree as a new GitHub
repository named `rust-pcap-analyzer`. That publication is source delivery only; it
does not establish native correctness, deployment, CI success, attack attribution, or
permission to read captures outside the user's authority, activate a network sensor,
or change an external system.

The objective is not a Wireshark replacement, a general DNP3 endpoint, an autonomous
attack detector, or a promise that Rust alone fixes semantic errors. A real-world
failure corpus is absent. Existing ecosystem bug reports motivated test families;
those reports are not a specification for reproducing another implementation's bugs.

### Route and operating reference

This is substantial work because untrusted binary input crosses several stateful
interpretation boundaries and forensic results may affect consequential decisions.
One serial integration owner changes source and package state. Public specifications,
exact source operands and independent fixtures own expected results.

The implemented operating lessons are source/authority separation, exact units, single
ownership, explicit negatives and unknowns, independent oracles, paired
positive/negative proof, bounded failure, and truthful delivery status.

### Policy decisions

1. Raw capture bytes are immutable input. Derived outputs name their source SHA-256.
2. Time is `(ticks, resolution, signed seconds offset)`. Integer nanoseconds are an
   optional exact projection, never the canonical clock. No rounding or synchronization
   is performed implicitly. Unknown time is not zero or outside every time window.
3. Packet IDs are capture digest + 1-based packet ordinal + raw record offset.
   Section/interface/VLAN identity constrains flows; identical tuples on different
   observation interfaces do not silently merge.
4. Valid container structure and valid packet semantics are distinct. Strict mode
   rejects contradictory captured/original lengths. Evidence mode retains readable
   contradictions with warnings, but never permits an out-of-bounds read or repairs
   the bytes. Unknown link/protocol types remain packet observations.
5. TCP overlap defaults to rejecting conflicting regions as explicit gaps. First/last
   observed policies are explicit alternatives with retained conflict diagnostics.
   These policies do not assert what an unknown target OS actually accepted. A
   closed generation is never reused for later payload, SYN, RST or unrelated
   non-SYN traffic. The one exception is an exact final ACK for an observed
   two-sided FIN teardown; without that narrow match or a new SYN, a plausible
   late packet remains unassigned rather than being merged into an old connection.
6. Lost bytes are not synthesized. Separate contiguous chunks do not become one
   application message across a gap or invalid link frame. Incomplete assemblies
   remain visibly incomplete.
7. A TCP generation, protocol message, transaction candidate and attack label are
   different identities. Correlation is many-to-many evidence, not attribution.
8. No probabilistic confidence number is invented. Status and reason carry the actual
   observable uncertainty.
9. The filesystem output path is a separate authority boundary. Reads never create
   sidecars; output is explicit and never overwrites an existing destination.
10. Unsupported capabilities and exhausted budgets fail explicitly. No “best effort”
    mode may silently label missing work complete.

### Current disposition

The snapshot and bounded streaming paths are locally validated with Rust 1.85.1
on Windows. Root and streaming check/test/release/format/Clippy gates passed;
the root inventory contains 135 selectors with 133 collected on Windows, the
streaming contract suite has 40 tests, the Python evidence suite has 68 tests
and 23 subtests, and the three semantic mutants were killed. Both optional fuzz
workspaces compile. Cross-platform CI observations, fuzz campaigns, real-capture
replay, performance qualification and security review remain unproved. Criteria
are locally witnessed against synthetic fixtures, not production-qualified.

## 2. System and criteria ledger

### Ownership and producer → carrier → consumer

| Owner | Input and responsibility | Consumer / canonical output |
|---|---|---|
| `capture` | bytes; framing, section endian, interface state, bounds | raw `Record`, `PacketMeta`, structured error |
| `time` | raw capture operands and units | exact `Timestamp`; explicit failed projection |
| `wire` | packet bytes + scoped packet identity | network/transport views with source spans |
| `fragment` | scoped IP fragments and capture ordinal | complete datagram or pending/rejected/expired evidence |
| `tcp` | scoped transport segments and optional times | generation assignment, stream chunks, gaps, conflicts |
| `dnp3` / `modbus` / `protocol` | contiguous TCP spans, configured UDP datagrams, declared protocol policy | frames/messages/incomplete state, advisory probes, no inferred missing bytes |
| `correlate` | messages and separately supplied labels | bounded transaction/attempt candidates, reasons |
| `engine` | complete bounded snapshot and immutable config | terminal packet ledger + reconstruction report + datagram-local application evidence |
| `index` | source snapshot; optional untrusted sidecar | verified source-bound packet lookup |
| `report` / `json` | typed model | deterministic, bounded JSON projection |
| `publish` | explicit path and serialized bytes | no-clobber publication or typed pre/post-commit failure |
| `writer` | explicit valid packet/interface operands | new container; poisoned writer after partial I/O failure |
| `sha256` | bytes only | content digest, not authentication |
| CLI | arguments → immutable source → engine/report | stdout or explicit new file and distinct exit status |

There is no database or hidden cache in the snapshot runtime. Source capture is the canonical evidence;
indexes/reports are reproducible projections. The full analyzer is intentionally
single-process and snapshot-based. Streaming container parsing is available
as a sibling crate governed by `docs/streaming/CONTRACT.md`. Its protocol and TCP
state are explicitly bounded by windows; this is not a lossless, disk-spilling
distributed 200 GB analysis implementation. Add such a backend only with an actual workload,
recovery contract and measured same-output comparison.

### Hard criteria and proof owners

| ID | Acceptance / rejection boundary | Construction owner | Independent witness and native selector |
|---|---|---|---|
| C01 container fidelity | same packet bytes, frame boundaries, endian/interface scope; reject truncation and malformed trailers | `Decoder`, `CaptureIter`, `CaptureReader` | Python `struct` oracle + `capture_contract::four_pcap_magic_forms_preserve_units_and_bytes`; mixed-sections and one-byte-read tests |
| C02 numeric semantics | preserve all resolution octets and signed offsets; refuse inexact projection | `Timestamp`, `Resolution` | Python `Fraction` + `integrity::every_resolution_octet_round_trips_without_high_bit_loss`, `capture_contract::binary_timestamp_inexactness_is_explicit` |
| C03 packet identity | every successful analysis packet has exactly one terminal disposition; spans reconstruct exactly | `EvidenceBytes`, engine `each_packet` | black-box `check_cli.py` source-byte rebuilding + `protocols::end_to_end_fragmentation_keeps_all_packet_dispositions_terminal` |
| C04 link/network truth | apply correct link offsets and IP lengths; captured bytes bound all reads | `wire` | handwritten protocol fixture fields + `wire::original_length_never_authorizes_read_beyond_captured_bytes` and L2 variant tests |
| C05 IP reconstruction | no overlap-conflict laundering, no lost contributor IDs, no silent expiry | `FragmentReassembler` | manually specified spans + `reconstruction::conflicting_ipv4_fragments_quarantine_set`, IPv6 overlap and duplicate-neighbor tests |
| C06 stream semantics | no duplicate payload; conflict/gap remains explicit; no arbitrary generation assignment | `StreamAssembler`, `TcpTracker` | independent byte literals + conflict, reorder, SYN/FIN and reuse tests in `reconstruction` |
| C07 DNP3 framing | CRC boundaries, 6-bit/4-bit rollover, separate unsolicited and incomplete state, datagram-local UDP dispatch | `dnp3::decode`, engine dispatch | external CRC check vector + independent Python frame builder/oracle + TCP and configured-UDP DNP integration tests |
| C08 Modbus roles | MBAP/message limits; server role from declared service endpoint, not SYN initiator; response shape consistency | `modbus::decode`, engine dispatch | server-initiated fixture + `protocols::modbus_server_initiated_tcp_does_not_invert_protocol_roles` + response-consistency tests |
| C09 correlation authority | labels cannot change reconstruction or turn unknown into negative/attack truth | `apply_labels`, candidate matching | unchanged-flow black-box comparison + label invariance and missing-time tests in `integrity` |
| C10 sidecar integrity | rehashed forged metadata still rejected; extracted bytes exclude container headers | `VerifiedIndex::load` | independently changed/rehashed carrier + `integrity::sidecar_self_hash_cannot_authorize_forged_metadata` |
| C11 external effects | no overwrite, no source mutation, one publication winner, explicit poisoned writer | `publish`, writer failure state | process/filesystem witnesses in `integrity`, `cli`, `capture_contract::partial_write_poisons_writer_and_blocks_unsafe_retry` |
| C12 bounded/observable delivery | configured limits reject rather than truncate; every proof tier reports actual execution | `Limits`, typed errors, validation script | hostile-input suite, exact limit neighbors, retained tool output and package manifest |
| C13 source publication | requested repository contains the reviewed synthetic source and truthful status files, with no private captures or secrets | Git integration and publication owner | remote repository metadata/tree plus local source identity; publication is not native proof |

The exact source test inventory is `tests/TEST-MANIFEST.json`. Inventory existence is
not evidence of execution. Optional tuning can never relax bounds implicitly or
promote an unsupported result to verified.

### Clocks, lifecycle and capacity

Capture order drives fragment expiry; wall-clock time at analysis is not involved.
TCP idle grouping uses exact available capture timestamps and preserves unknown-time
cases. Out-of-order timestamps and unsynchronized observation sources remain possible;
the system does not apply guessed offsets. TCP sequence comparisons are bounded below
half the u32 sequence space and reject the exact half-space ambiguity.

Default source cap is 256 MiB, block cap 16 MiB, packet cap 1 MiB, record cap 1,000,000,
interfaces 1,024, flows 4,096, segments per stream 16,384, stream span 4 MiB, retained
TCP payload 64 MiB, fragment sets/parts 1,024 each, application bytes 1 MiB, protocol
messages 100,000, labels 10,000 and correlation comparisons 5,000,000. See `Limits`
for canonical values and units. Fragment lifetime is 100,000 capture frames. CLI
encoded JSON cap is 512 MiB. Defaults are safety clamps, not benchmark-derived SLOs.
They do not add up to a bound on total allocator overhead, report-tree memory or CPU.

A stream, fragment or application budget breach is a visible rejection/failed scope,
not a smaller successful result. The batch analyzer can return an error without a
partial report on a hard global limit; the low-level streaming reader is the explicit
alternative for record-by-record handling.

Generic writer I/O can partially commit bytes. After such a failure, that writer is
poisoned and cannot be reused. Prevalidation rejection does not poison a writer.
Filesystem output uses an independent no-clobber publication protocol and requires
a trusted stable parent directory. Directory durability on non-Unix is not asserted.

### Alternatives and deliberate exclusions

A libpcap wrapper would add native deployment and a flatter PCAPNG API. An Arkime
integration would introduce a different application/runtime rather than an embeddable
Rust foundation. This implementation instead keeps original local parsing code and
no runtime dependencies, accepting the obligation to validate that code independently.
Neither alternative is declared universally inaccurate or inferior.

No mmap/async adapter is advertised: both can later share `Decoder`. No OS overlap
policy is inferred; no protocol is guessed solely from plausible payload bytes when
that would authorize correlation. No full DNP3 object decoder, TLS decryption,
compressed input, Wi-Fi dissection, arbitrary tunneling, ICMP sessionization, SCTP,
NAT inference, capture-clock repair, distributed storage or attack classifier is
implemented. These remain explicit capability boundaries rather than empty stubs.

## 3. Test evidence ledger

### Representative surface and independence

The included synthetic cases cover binary container and state-transition edges,
not a complete real-world workload. Fixture bytes are produced using a separate Python
`struct` builder. A second Python reader with `Fraction` and `hashlib` evaluates
handwritten expectations. Neither imports Rust source or gets expected results from
the candidate's JSON. The native black-box bridge compares those independent results
to the real CLI and rebuilds exported spans directly from original packet bytes.
Independent implementations still share assumptions; specifications and reviewed
truth fixtures are the adjudicator, not majority agreement.

| Predicate | Intended case | Nearest negative | Sibling | Unknown/boundary |
|---|---|---|---|---|
| exact time | decimal micro/nanoseconds | invalid fraction | binary resolution, signed offset | sub-ns/inexact or absent timestamp |
| reconstructible bytes | reordered unique segments | conflicting overlap | identical retransmission | leading/middle/trailing gap, ambiguous generation |
| DNP3 continuation | valid CRC + next sequence | corrupt link frame | rollover 63→0 and 15→0 | incomplete transport/application assembly |
| label match | observed tuple + inclusive time | other tuple/window | reverse packet direction | unavailable exact time |
| trusted index | canonical source-bound metadata | forged entry with rebuilt self-hash | wrong source identity | unsupported/truncated schema |
| publication | new trusted destination | pre-existing destination | racing writer/symlink | error before versus after commit |

Three executable semantic mutants target timestamp mode, conflict rejection and
sidecar source reconstruction. Each selected native test first passed unmodified and
then actually executed and failed under the mutation; all three were killed by their
named tests. A compile error or unreached selector is not accepted as a killed mutant.

The Python oracle's tests and fixture checks were executed. The Windows run
collected 133 of the 135 root selectors, and the streaming contract suite ran 40
tests; the hardening CLI oracle rebuilt 93 synthetic cases. See `VALIDATION.md`
and the source-bound receipts for exact commands/results. The optional fuzz
workspaces compile, but no campaign or coverage is claimed; cross-platform CI,
real-capture replay and deployment resources remain unobserved.

### Failure-family corrections retained in source

| Failure family | Earliest guard | Regression / inverse |
|---|---|---|
| refill at EOF never progresses | streaming reader fused terminal state | truncated tail vs one-byte valid reads |
| unit mask changes time silently | canonical `Resolution` conversion | all 256 encoded octets; binary exact/inexact |
| duplicated or contradictory stream data | interval sweep and conflict policy | duplicates accepted without duplication; conflicting bytes become gap |
| invalid DNP frame bridges application fragments | flush incomplete application state at invalid boundary | corrupted middle frame vs valid rollover |
| zero-length fragmented carrier erases provenance | reject empty real IPv6 fragment | legitimate atomic fragment remains decoded |
| unknown Modbus function presented as validated semantic pair | `semantics_supported` separate from frame validity | preserve raw message and explicit unsupported issue |
| partial I/O retry duplicates unknown output prefix | poisoned writer after first I/O failure | valid prevalidation rejection leaves writer usable |
| derived sidecar hash launders forged fields | recompute metadata from source before `VerifiedIndex` construction | forged+rehashed sidecar rejected; valid neighbor accepted |
| temporal/provenance claim alters underlying interpretation | reconstruction first; labels second | byte-identical flows/applications with/without labels |

These are implemented prevention controls with authored tests, **not claims of native
green proof**. No criterion closes from a source inspection alone.

## 4. Execution and promotion plan

1. Freeze the current contract, source hash and test inventory. Run the cheapest
   syntax/structural and independent fixture prerequisites; stop on failure.
2. On a machine with pinned Rust, run native check → debug tests → release tests →
   warnings-denied Clippy → binary build → both independent CLI oracles → semantic
   mutations. Retain commands, versions, output, source hash and execution status.
3. Run configured Linux/Windows/macOS CI and docs/examples. Observe results rather
   than assuming workflow presence equals execution. Format and review the actual
   diff before a public release.
4. Minimize a real-world disagreement with permission. Compare the first divergent
   layer and expected result independently; keep private capture data out of this
   public synthetic corpus. Add a de-identified or synthetic regression where valid.
5. Before accepting hostile uploads or scaling, run resource-contained fuzz campaigns,
   security review, sustained realistic captures and measured peak RSS/latency. Keep
   optional unknowns explicitly out of the promotion scope.
6. Package only reviewed source/tooling/synthetic fixtures/receipts. Verify ZIP members,
   source-file hashes and independently rerun portable checks after fresh extraction.
   For this task, publish that reviewed source to the requested GitHub repository only
   after the local portable checks and source identity are current, then verify the
   remote repository metadata and file tree. Archive integrity and source publication
   do not close native or real-corpus gates.

Current stop boundary: commit this reviewed local candidate after the completed
local native gate; merge/publication is a separately observed Git operation. Do not
deploy, read private captures, or claim production qualification.
Reopen on a real compiler/test failure, new protocol ambiguity, source/oracle
disagreement, scope change or representative corpus. Fix the smallest owning boundary
and its failure family without broadening attack authority.
