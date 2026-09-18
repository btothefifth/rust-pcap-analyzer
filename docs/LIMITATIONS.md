# Capability and evidence limits

## Native verification status

The configured Windows gate passed with Rust 1.85.1 and the native linker. It covered
formatting, compilation, debug/release tests, warnings-denied Clippy, the binary
build, independent CLI comparison, the 93-case hardening CLI oracle and three
semantic mutations. The test manifest contains 130 selectors; 128 ran on Windows and
two Unix-only selectors were not collected. A configured CI workflow is not a CI
result, so no Linux/macOS execution is claimed.

No real-world capture, independent operator acceptance, fuzz campaign, performance SLO,
or independent security audit is claimed.

## Scope is explicit, not Wireshark/Arkime equivalence

Container support includes raw preservation of known/unknown metadata, not exhaustive
semantic decoding of every option/extension. Legacy PCAP versions other than 2.4 and
PCAPNG versions other than 1.0 are rejected. Readable anomalies in Evidence mode do
not make malformed structure acceptable. Salvage is an explicit bounded section-
search helper, not automatic repair, arbitrary packet resynchronization, or proof of
the skipped region. Compressed captures are not transparently decompressed.

Packet support is Ethernet/VLAN, SLL/SLL2, raw IP and loopback with IPv4/IPv6 and
TCP/UDP. There is no radiotap/Wi-Fi, ARP semantic decoder, general tunnels, SCTP,
ICMP sessionization, TLS decryption, HTTP/DNS framework or complete protocol catalog.
Unsupported packets remain observations with a reason; this does not decode them.

DNP3 support is passive framing/reconstruction: link CRCs, transport and application
fragments, headers, unsolicited handling and transaction candidates. Configured-port
UDP analysis is datagram-local; it does not reorder, retransmit, or join separate UDP
datagrams. Object bodies are opaque. Full IEEE1815 object/qualifier semantics, secure
authentication and all vendor variations are not implemented. This is not an
interoperable DNP3 endpoint. Modbus common PDU shape and response consistency checks
do not establish every function/register/device semantic; unsupported function
semantics are explicitly marked.

## Offline inference is not endpoint truth

TCP generation assignment, idle boundaries and connection closure are conservative
inferences. Sequence windows do not prove a complete TCP state machine. No target OS
is guessed; first/last overlap policies are not advertised as Linux/Windows emulation.
Capturing midstream, missing SYN/FIN, simultaneous opens, NAT, reused tuples, clock
discontinuities and ambiguous delayed packets can prevent unique assignment. A
plausible generation is not proof of the endpoint's actual history. Once a
generation is closed, later payload, SYN, RST or unrelated non-SYN packets on the
same tuple are left unassigned until a new SYN provides an explicit generation
boundary. The only post-close exception is an exact final ACK for an observed
two-sided FIN teardown. This preserves ambiguity between a delayed packet and
tuple reuse.

IP fragment ID collisions and expiry are handled within bounded scope, not magically
resolved. IPv4/IPv6 overlap policies intentionally differ. The engine uses the
completing fragment's timestamp for reassembled transport processing, while each
original packet keeps its own raw timestamp for evidence matching.

Source packet identity is a content identifier, not a cryptographic attestation of
who captured the traffic. File offsets and digests alone do not establish chain of
custody. Test receipts do not confer attack attribution.

## Resource and storage envelope

The full analyzer operates on an in-memory immutable snapshot. Default input is
256 MiB, not 200 GB. Raising that limit does not raise every flow/segment/application
budget or turn the engine into streaming out-of-core analysis. The synchronous
container reader is separately streaming, but still bounded by configured input and
record limits. There is no mmap/Tokio adapter, database, automatic spool, parallel
flow executor or distributed index.

Limits bound logical work and selected payload sizes; object overhead, clones,
interval/provenance metadata, report trees and process runtime add memory/CPU. Final
JSON encoding is bounded, but its typed report tree already exists before encoding.
Allocation failure and pathological resource pressure are not eliminated by safe
Rust. Use OS-level memory/time limits for untrusted inputs until measured qualification.
No throughput/latency or zero-copy end-to-end claim is made.

Index build/load scans the source and canonical metadata. Only subsequent packet
lookup benefits from a verified in-memory index; timestamp searches currently scan
entries. The sidecar is a correctness-first source-bound projection, not a proven
large-scale performance improvement.

Generic `Write` output can be partial on I/O failure and must be discarded. Filesystem
publication requires a trusted stable destination parent and hard-link support.
It does not defend against an adversary concurrently replacing the parent namespace.
On non-Unix, directory-sync durability is not asserted. After a post-commit failure,
an output may already exist: inspect rather than silently overwrite/retry.

## Evidence and labeling

All fixtures are synthetic. Python's 10 tests validate independent fixture/oracle
logic, while the native Windows gate provides the local Rust execution evidence. The
native test inventory is not proof of complete coverage. Fuzz harnesses alone say
nothing about campaign duration, coverage or undiscovered defects. On the validation
host the fuzz workspace could not be checked offline because `libfuzzer-sys` was not
cached, and the campaign runner correctly blocked because it requires a POSIX worker;
no fuzz pass is claimed.

External labels correlate observed tuples/time spans. They do not prove attacks,
intent, attribution, success or a one-to-one attack/session relationship. Missing
exact timestamps are unresolved, not no-match. No numerical confidence estimate is
emitted because no calibration study exists.

## Release work still needed

Complete multi-platform checks next. Then replay at least one minimized known real-world
mismatch, adjudicate the first divergence against independent expected evidence, and
add that failure family without weakening existing valid-neighbor tests. Conduct
bounded fuzzing and measured workload/security qualification before exposing this
parser as an upload-facing service. New protocols and out-of-core processing require
their own criteria, implementations and proofs.
