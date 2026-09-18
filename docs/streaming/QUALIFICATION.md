# Integration and qualification procedure

The current source passed the configured Windows native gate with Rust 1.85.1.
This document defines the next qualification work; the local receipt is not a
cross-platform or production release gate. Inspect the formatted code and fix
localized compiler/lint failures without weakening evidence contracts. Refresh
the source inventory and receipts after every source change.

## Native and cross-platform gates

Use Rust 1.85.1 for the declared baseline, then test the intended deployment
compiler separately. Run root and streaming debug/release tests, Clippy with
warnings denied, rustfmt checks and examples. Observe actual Linux, Windows and
macOS CI results; the included YAML is not a CI result. Validate partial writes,
no-clobber publication, path collisions, stdin pipes and failure exit codes on each
platform. Use trusted directories and immutable input snapshots.

The optional independent parser oracle and fuzz workspace need reviewed dependency
acquisition and their own lockfiles. Neither dependency is required for normal
root or streaming builds. Do not confuse a missing optional tool with a pass.

## Corpus intake

Only the small upstream Wireshark DHCP test capture is currently hash-pinned in the
manifest. Its origin as a production recording was not independently established.
The handoff redistributes no third-party packet data. Review upstream rights,
operator authority, privacy, secrets and retention before adding more captures.

```sh
python tools/evidence_tool.py corpus fetch corpus/manifest.json corpus/local --allow-network
python tools/evidence_tool.py corpus verify corpus/manifest.json corpus/local
```

Network fetching is explicit and limited to approved HTTPS hosts, exact expected
length and hash. A moving upstream URL cannot silently replace the pinned bytes.
Add independently sourced messy PCAP/PCAPNG covering mixed sections/interfaces,
missing/inexact clocks, snaplen truncation, offload checksums, reused tuples,
reordering, conflicting retransmissions, tunnels and industrial protocols.
Preserve acquisition details and expected semantic observations separately from
the parser that generated the fixtures. Synthetic valid/invalid neighbor pairs
remain useful but do not replace diverse operational captures.

## Differential comparison

```sh
python tools/evidence_tool.py differential corpus/local/dhcp.pcap receipts/dhcp-diff --binary streaming/target/release/pcap-stream --semantic
```

The first layer compares packet ordinals, lengths, offsets, raw identity and exact
time where supported. TShark encapsulation identifiers are not assumed equal to
PCAP LINKTYPE values. The independent optional `tools/pcap-parser-oracle` checks
packet lengths/counts and does not depend on `pcap-evidence`.

Zeek and Suricata can be executed with logs retained, but their connection/log
records are different-grain observations. The current tool does **not** implement
a complete cross-engine semantic normalizer or declare them equivalent simply
because they exited successfully. Adjudicate discrepancies in this order:
container bytes/clocks, packet decode, fragment reconstruction, tuple/generation,
selected stream bytes, protocol messages, transactions, external labels.

Record exact tools/versions/options, source digest, first differing fact, chosen
specification requirement, alternative valid interpretations and final regression.
Do not vote across tools: several tools can share the same assumption or bug.

## Minimize a specific mismatch

Provide a trusted predicate program that returns 0 only when the same identified
mismatch persists, 1 when it does not, and another status on execution errors.
`{capture}` is replaced with the candidate pathname; no shell interpolation occurs.

```sh
python tools/evidence_tool.py minimize source.pcap reduced.pcap -- python specific_mismatch.py '{capture}'
```

The reducer bounds input size, packet count, calls and execution time. It produces
a derived packet-subset artifact plus a frame map. Packet bytes remain exact, but
nonessential container metadata may be omitted and finite PCAPNG section lengths
become unknown. This is not archival copying or arbitrary malformed-byte reduction.
Keep the original hash and license/provenance with each minimized regression.

## Fuzzing

Read `streaming/fuzz/README.md`. Acquire cargo-fuzz/libFuzzer through the normal
trusted toolchain process on a POSIX worker, seed with independent valid and hostile
samples, run existing and new targets, retain exact coverage/runtime/crash receipts,
then minimize and promote failures into deterministic tests. Reproduction must use
the same source/config/seed identity.

```sh
python tools/evidence_tool.py qualify . receipts/fuzz-run --fuzz-seconds 3600
```

The driver labels shorter runs as smoke-only. One hour or any other duration is not
a coverage/completeness guarantee. No campaign was executed on the authoring host.
Process logs and timeouts are bounded, but subprocess monitoring is not a complete
host sandbox; apply independent OS/process-tree resource limits.

## Large-file qualification — required before 50–500+ GB claims

The supplied benchmark generator streams synthetic DNS/UDP captures to disk. It
checks free disk and never creates a giant capture without an explicit command.
See `benchmark generate --help` and `benchmark run --help` for exact switches.
Do not infer real-corpus throughput or TCP completeness from synthetic DNS.

Measure representative workloads at increasing sizes, including long-lived TCP,
many short flows, tiny packets, high duplicate/fragment counts, tunnels and huge
metadata output. Record input rate, user/system CPU, external peak RSS, output
bytes per input byte, disk write amplification, index size, query latency, replay
verification cost, event count and every emitted history cut. Use the same config
at each size and inspect the whole run, including shutdown/EOF flush.

Required acceptance evidence includes no file-size-proportional retained state,
no silent event loss, bounded collection capacities under worst-case inputs,
correct source hash and packet conservation, deterministic replay, and declared
acceptable application coverage across cuts. A 500 GB read that produces many
incomplete sessions is not full-fidelity 500 GB analysis. Out-of-core source
reading and bounded windows are implemented; full-history disk-spooled session
reconstruction and production-scale performance remain separate engineering work.
