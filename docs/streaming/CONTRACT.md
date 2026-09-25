# Streaming evidence contract — candidate v1

This is the written contract for the delivered source. The local Windows native
gate for the current source passed; that is not a claim of API stability,
cross-platform CI success, production qualification or real-world protocol
coverage. The remaining boundaries are recorded in `docs/VALIDATION.md` and
`docs/DESIGN_GAPS.md`.

## Two analysis paths

The existing `pcap_evidence::engine::analyze(&[u8], Config)` remains the bounded
snapshot API. The sibling `pcap_evidence_stream::analyze_reader(Read, StreamConfig,
&Registry, &mut EventSink)` is the incremental path. It uses the existing validated
container decoder, provenance buffers, IP reassembler and TCP tracker rather than
inventing an unrelated interpretation of those layers.

The new crate is a separate workspace with a path dependency on the root. It does
not introduce a third-party dependency into ordinary library or CLI execution.
Python/SQLite is optional downstream tooling, not part of the Rust runtime.

## Memory, ordering and reconstruction windows

Packet and container metadata events are produced as records arrive. TCP chunks
and protocol messages are produced when a bounded active reconstruction window
is flushed. A slow sink blocks the producer; a sink error stops processing. There
is no unbounded internal event queue or final, capture-sized JSON tree.

An active key includes capture section, interface, VLANs, tunnel namespace,
transport and normalized endpoints. Within each key, the original TCP tracker
still distinguishes its conservative connection generations. A session ID names
an **analysis scope**, not an authenticated endpoint connection. A window ID names
retained reconstruction history. Neither can be assumed continuous across a cut.

Per-window packet references and payload, total retained TCP payload, active key
count, fragment state, tunnel contexts, detector prefix, plugin output and event
size have independent limits. Idle/pressure cuts emit `coverage.boundary`. Pending
fragments, unclosed flows, gaps, ambiguous assignments and rejected overlaps remain
observable. A missing timestamp is not zero and does not invent a time expiry.

The implementation discards reconstruction history at a window boundary. It does
not spool all TCP sequence history to disk, preserve cross-window messages, or
prove that a late retransmission is consistent with discarded bytes. The next
window is a new evidence scope; long-lived sessions can therefore have partial
application coverage. Raising input limits does not eliminate this tradeoff.

Logical payload limits are **not a hard process RSS guarantee**. Collection
capacity, provenance spans, packet references, plugin metadata, JSON trees and
allocator overhead consume additional memory. The driver preserves bounded
collections; trusted plugin code can still allocate or compute arbitrarily. Use
OS-level memory, CPU, disk and execution limits when processing untrusted captures.
Do not advertise 50–500 GB qualification before running `QUALIFICATION.md`.

## Stable identities during one-pass input

A source SHA-256 is not known until EOF. Every event therefore carries a caller-
chosen `run_id`, a monotonic event sequence and packet ordinal/record-offset
references. The final `capture.complete` binds that run to `source_sha256` and
`source_bytes`. Events without a valid terminal record are provisional; a
`capture.aborted` record binds only the consumed prefix and does not certify the
complete capture.

Internally, the reused root `PacketId.capture` field contains a **provisional run
namespace hash** on this path. Native plugin implementers must NOT interpret it as
the capture SHA-256. Event serialization deliberately omits that field and exports
run-relative packet references instead. Do not mix these packet IDs into the
snapshot API's source-bound indices. The final event is the authoritative source
binding for the streaming run.

Run IDs must be unique in the consumer's namespace for distinct runs. Replaying a
run for deterministic verification intentionally reuses its run ID and config.
Sequence, session, offsets, byte extents and exact timestamps are decimal strings;
JSON numbers are used only for bounded small fields such as ports and flags.
`timestamp_ns` is null when absent or not exactly representable; raw timestamp
clock metadata remains available in the packet event.

## Event envelope and byte representation

Each NDJSON line contains `event`, `previous_sha256`, and `event_sha256`. Event
fields are defined structurally by `event.schema.json`. `schema` is
`pcap-evidence.event.v1`. The callback API receives the typed `Event` before JSON
serialization; callback consumers need not parse text at all.

The first previous hash is 32 zero bytes. For every line:

```
SHA256("pcap-evidence/event/v1\0" bytes || previous_digest_32_bytes || exact_event_JSON_bytes)
```

The exact serializer output matters: reordering keys, altering whitespace or
normalizing number/string types changes the digest. The wrapper and trailing
newline are not included in that event's digest. Byte-preserving transport is
required; prefer CLI `--output` to legacy PowerShell text redirection.

A hash chain detects corruption and binds order. It does **not** authenticate the
producer or prevent an adversary from rewriting and rehashing the entire log.
Trusted-source semantic replay is required to validate derived analytics facts.

Statuses are `observed`, `candidate`, `ambiguous`, `incomplete`, `unsupported` and
`rejected`. They describe evidence interpretation, not calibrated probability,
attack classification, attribution, or successful device execution. A completed
container read can contain many incomplete/unsupported observations. In
particular, `capture.complete` explicitly sets `complete_protocol_history=false`.

Event kinds cover capture start/complete/abort/metadata, packet/network observation,
network reconstruction, flow start/end, stream chunks/gaps/conflicts, protocol
selection/messages/issues, generic transaction candidates, the separate
`dnp3.confirmation_candidate` projection, diagnostics and coverage cuts.
The DNP3 projection is TCP-only, source-bound and scoped to one capture/session/
window/generation; it retains exact fragment participant evidence and does not
change generic transaction events or pair separate UDP datagrams. Consumers
should retain events whose types they do not yet interpret. A future incompatible
contract must change the schema identifier; v1 is still a release-review
candidate, not a promised Rust ABI.

## Provenance and relations

`evidence.spans` maps a reconstructed half-open `[start,end)` interval to a source
packet at `packet_start`, identified by `frame` and `record_offset`. Selected byte
spans are ordered and contiguous where a reconstruction claims contiguous bytes.
`evidence.packets` can include additional contributors, such as ACKs or duplicates
that did not supply selected bytes. Empty spans are not fabricated byte evidence.
`reconstructed_sha256` hashes selected reconstructed bytes; it is null for events
that contain only references. `byte_length` is the selected byte extent.

`stream_range` is a signed, half-open range in one directional reconstruction.
`related_events` references already-emitted message/event sequence IDs. Transaction
candidates use those references rather than copying payloads. The analytics builder
propagates their packet associations, making transaction time queries meaningful.
Conflicting alternatives must not be laundered into a single apparently certain
byte sequence. Preserve the configured overlap policy and conflict evidence.

## Plugins

`ProtocolDetector` returns NoMatch, NeedMore, or a bounded structural match.
Every detector runs on the same allowed prefix; all simultaneous matches are
retained. Built-in detection does not primarily require standard ports. Optional
configured-port fallback is explicit and off by default in the streaming crate;
the snapshot compatibility path retains its reported fallback behavior.

`AnalyzerPlugin` constructs `StreamAnalyzer` or `DatagramAnalyzer` instances with
`AnalyzerLimits`. A stream analyzer accepts contiguous provenance-aware chunks;
`gap` is a mandatory reset/incomplete boundary. A datagram analyzer receives one
reassembled UDP datagram, never joined independent datagrams. `Output` enforces
message/event limits and routes provenance through the sink. The DNP3 projection
reuses CRC-verified fragment witnesses and rejects ambiguous flow context, gaps,
conflicts and unverified boundaries as candidates. `TransactionCorrelator`
is replaceable and sees bounded message records, not an unlimited capture graph.

Plugins must emit object-valued JSON metadata, preserve supplied byte provenance,
report unsupported/truncated semantics, propagate output errors and honor their
budgets. They must not perform I/O in detectors, infer authentication from a
signature, bridge gaps or hide competing detector matches. The API executes trusted
in-process Rust; it is NOT a plugin sandbox.

The complete example `streaming/examples/custom_plugin.rs` registers an independent
UDP marker protocol without editing `runner.rs`. It is included in `--all-targets`
build/test gates. It demonstrates registration and provenance, not a production
network protocol. The current driver flushes bounded TCP windows into plugins;
a future continuously incremental/disksupported engine can reuse these traits but
must retain the same explicit history-boundary contract.

## Privacy and output ownership

Packet/stream payload export is off by default. Metadata can nevertheless contain
names, URLs, network identities, SNI, DHCP identifiers or sensitive application
information. Credential-bearing HTTP headers are omitted; this is not a universal
redaction system. PCAPNG decryption-secret bytes are not exported.

Normal CLI file output is no-clobber and uses a temporary file plus hard-link
publication in a trusted stable parent. A failed writer is not resumed. Hard-link
support is required; post-publication durability failures can leave an output
present. Inspect before retrying. Stdout/pipes can contain an incomplete prefix on
error and must not be accepted without successful final binding.

## Analytics verification

The Python SQLite projection adds time, tuple, session, protocol, application-
metadata and evidence relations without holding the whole log in RAM. The original
`.pcidx` format remains unchanged, with an added in-memory sorted time cache for
its verified immutable source snapshot.

Building the SQLite index validates the event chain and source packet claims but
sets `semantic_replay_verified=false`. `index verify` runs a trusted analyzer with
recorded config on the immutable source, rebuilds the projection, and compares all
canonical tables. Neither a file hash nor an index self-hash establishes semantic
correctness. Verification requires disk for a second log/database and a source
replay. Different plugin sets need an explicit compatible verifier; the provided
CLI verifier is for the built-in configuration surface, not arbitrary plugins.
