# Disk-retained TCP research history, version 1

## Supported transformation and authority

`history/` is a separate standard-library-only Rust workspace. It reuses the
project's independently implemented container, network and fragment decoders;
it does not consume another analyzer's interpretation. The existing snapshot
and bounded-streaming APIs are unchanged.

The new path is:

    source identity pass -> incremental capture parsing -> packet witnesses
       -> scoped TCP generation/epoch hypotheses -> append-only journal
       -> bounded external sort -> source-checked interval queries

This implements automatic **TCP observation retention and generation/sequence
hypotheses** across in-memory tuple evictions. It is not yet complete application
reassembly across arbitrary histories. `complete_application_history` is always
false. The new CLI does not emit the existing streaming event schema: history has
separate, explicitly versioned native and JSON contracts. It must not silently
replace the existing GUI/streaming engine.

## Sources and provenance

Two streaming source passes bind the journal to a complete SHA-256 and byte count.
The first identifies the source; the second parses it while independently hashing
all records. A disagreement prevents a seal. This means initial source identity
requires a full read before TCP analysis begins; it is not a zero-latency/live mode.

Packet records retain original ordinal, record/data offsets, captured/original
lengths, link type, section/interface, exact raw clock representation and raw
record/packet hashes. Missing or inexact timestamps do not become zero. Each TCP
record retains the original TCP header and payload plus contiguous source spans.
A reconstructed fragmented TCP record may have many original packet witnesses.
Checksum failures remain observations rather than repaired data.
Unsupported transport pseudo-header operands produce explicit journal notices
for outer UDP and TCP; TCP decisions also retain the uncertainty reason in range
output. Observation mode preserves source bytes without labeling those checksums
valid or invalid.

The caller must keep the source immutable in a trusted stable filesystem namespace.
The workspace is created exclusively. The parser does not overwrite captures,
follow final-path symlinks, fetch dependencies, contact services or acquire traffic.
No claim is made against a local adversary able to replace parent namespaces or
modify the process. Raw stored TCP may contain private data: keep workspaces local.

## Tuple, generation and sequence ownership

Keys include ordered endpoints, capture section/interface, the separate optional
SLL2 link-header interface index, VLAN IDs and a bounded
tunnel path. Tunnel scopes include canonically ordered outer endpoint identities;
reverse directions share the same tunnel namespace, while GRE keys and
VXLAN/Geneve VNIs remain separate. A generation
identifier is derived from source identity, key, birth frame and generation ordinal.
It is an analysis identity, not proof of an endpoint's actual connection history.

An observed SYN without ACK establishes a generation candidate. Repeated identical
open SYNs and simultaneous-open shapes remain explicitly described hypotheses.
SYN-ACK association checks observed peer SYN information where available. Missing
handshakes remain midstream. FIN positions and RST are retained. Closed generations
are not discarded merely because a later tuple is reused: late observations can
remain candidates for old and new generations.

Raw TCP sequence numbers are mapped into candidate 64-bit offsets, considering
32-bit sequence epochs within a configured observation horizon. Default policy is
`StrictAlternatives`: multiple plausible generations or epochs remain unselected.
The engine does not invent an endpoint OS or use analyzer votes.

`NearestFrontier` is a separately selected, explicit hypothesis: among multiple
epochs belonging to the same generation, a unique closest frontier may guide state
progress. Every alternative is still retained and the decision records the
assumption. It never chooses among multiple generation identities. More than one
sequence wrap is representable, but capture bytes do not establish which epoch is
correct merely because this policy selects one. Strict mode may stop advancing
state in long ambiguous histories; that is a visible limit, not successful lossless
reconstruction. Exhausting the epoch or generation budget aborts the candidate.

Capture timestamps only record ordering uncertainty. The history engine does not
expire state using wall-clock time. TCP timestamp options are retained/validated as
wire observations, not used as authenticated PAWS or endpoint state evidence.
Window zero is noted; window scaling and a complete endpoint TCP state machine are
not implemented. Gaps, payload after FIN, conflicting FINs, absent timestamps and
clock reversals remain explicit where observed.

## Journal wire format

All integers below are little endian, except raw protocol bytes. Integers are fixed
width, not host layouts. Binary fields are never produced by serializing a Rust
struct's memory representation.

Header: `PCHIST01`, u32 body length, body, SHA-256(prefix + body). Body is source
SHA-256[32], source length u64, length-prefixed canonical configuration. Config begins
with the engine/policy version string, followed by 15 u64 budgets and one epoch-policy
byte. The current engine identity is `pcap-evidence-history/2;state-policy/1`;
older engine identities fail closed and require a fresh source replay. Tuple keys
encode section u32, container interface u32, canonical link-interface presence
byte and optional u32 value before VLANs, tunnel path and endpoints. Exact field
order is in `model::Config::encode` and the independent Python reader.

Engine 2 binds the separate SLL2 link-interface namespace and uses canonical
bidirectional tunnel identity. Engine 1 stores lack that key representation and
may contain direction-split tunnel generations. Readers, queries, verification
and recovery reject the earlier identity with a rebuild reason: retain the
earlier store as historical evidence and rebuild into a new workspace from its
immutable original capture. Changing a stored engine label or rehashing an old
journal cannot migrate its decisions or indexes and is not supported.

Record: u32 payload length, u8 kind, u64 ordinal, body, digest[32]. Payload length
includes kind + ordinal. Digest domain is `pcap-evidence/history-record/v1\0`, followed
by preceding digest, exact length bytes and payload. Types: packet=1, TCP=2,
notice=3, checkpoint=4, abort=254, seal=255. Unknown types, changed ordinals, length
violations, hash disagreement, noncanonical fields and data after terminal fail.

TCP body contains separately length-prefixed input and decision. Input includes
scope, direction, frame, optional signed i128 capture time, raw TCP bytes and source
witnesses. Decision includes before/after canonical state hashes, an assumption
flag, all placement alternatives and reason strings. A state hash is an auditable
identity, not a proof of correct TCP interpretation.

`packets.idx` has fixed 80-byte rows. `ranges.idx` has fixed 112-byte rows sorted by
generation, direction, start, end, journal ordinal and remaining tie breakers.
Rows bind their placement to a journal offset/digest. The final seal binds counters
and both index identities. Temporary sort files and tuple caches are workspace-owned.

## Bounded RAM, disk and interruption

Defaults: 64 hot tuples; 128 generations per tuple; 16 epoch candidates; 2 MiB
record limit; 32,768 sort entries; merge fan-in 16; 64 KiB query range; 4,096 query
intervals; 128 MiB logical query-work allowance. The interval budget bounds every
sequential index row fetched, including rows filtered before the requested start
and the terminating row. Query work charges the fixed index-row bytes separately
from selected journal bodies, source witness bytes and piece comparisons. Source
and logical workspace quotas
default to 1 TiB and can be lowered. The CLI exposes important build budgets; the
native `Config` exposes every limit. These are limits, not demonstrated capacity.

A tuple eviction spills its complete bounded generation state; later observations
reload it. The cache never becomes imported authority: restart reconstructs from
the original source and checks the valid journal prefix. A state store is poisoned
after failure, rather than continuing after lost eviction state.

Recovery validates EOF after a complete seal or abort; any trailing byte fails,
including when torn-tail recovery is authorized. That authorization applies only
to an incomplete final record before a terminal record. Replay comparison omits
the terminal record so that a clean aborted prefix can produce a new sealed replay.

External sorting uses bounded chunks/fan-in and cooperative cancellation during
run generation and merge phases. Buffers are bounded and disk charges include
logical journal, indexes, state caches and temporary sort contents. File allocation
blocks, directory entries, filesystem metadata, allocator overhead and OS caches
are not a hard RSS or physical filesystem quota. Apply OS quotas for hostile workloads.

Checkpoint and terminal publication flush file buffers and fsync. POSIX directory
sync is attempted; Windows directory durability is not asserted. A write/flush error
poisons the writer. Partial/torn output is never sealed by retrying an uncertain write.
Library callers can trigger `Cancellation`; abrupt CLI termination leaves an unsealed
prefix. Cancellation during hashing/index verification may wait for a bounded I/O
operation; interruption is not a hard real-time guarantee.

`recover` always writes a NEW workspace and replays the source. It verifies that the
valid old journal prefix is reproduced. `--allow-torn-tail` authorizes only a truncated
final outer record, never an interior hash mismatch or malformed complete record.
This is restart-by-replay, **not checkpoint-position resume without rereading**.

## Query truth and verification levels

`History::open` checks source identity, the complete journal chain and sealed index
identities/order. Queries re-read selected source spans and verify stored TCP bytes,
record digests and placement membership. Output contains each contributing observed
interval. Conflicting byte alternatives are not first-wins, last-wins or majority-wins.
Unselected placements are not silently promoted. Missing ranges remain gaps.

The independent Python verifier checks container metadata, clocks, source witnesses,
checkpoint framing and index membership. It intentionally does **not** validate the
TCP state transition policy or label semantic replay true.

`pcap-history verify` regenerates the journal AND both indexes from the source and
recorded configuration and compares exact identities. This establishes same-engine,
same-policy reproducibility, not normative correctness, independent authorship,
endpoint behavior, authentication or a chain of custody. Do not relabel it an
independent semantic oracle.

## Remaining boundaries

IP-fragment retention is still bounded by the inherited reassembler (16 contexts,
1 MiB per context, 32 sets, 128 fragments/set in this path), with explicit notices
on expiry/reset. No unlimited IP-fragment spool is claimed. Non-TCP packets remain
source-addressable but are not given TCP history. Generation queries currently list
payload-bearing hypotheses, not all zero-payload connections. There is no automatic
cross-history application parser/correlator, history GUI view, distributed history,
TLS decryption, zero-copy claim, native installer, or measured 50–500 GiB qualification.

Native unit/integration/fuzz source exists. It must be compiled and exercised on the
recorded repository/toolchain before this candidate is promoted.
