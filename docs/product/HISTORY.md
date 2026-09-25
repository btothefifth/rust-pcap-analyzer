# Source archive and stream-hypothesis store

## Exact source retention

`archive(source, destination, chunk_bytes=4 MiB, disk_budget=1 TiB)` reads a regular
capture incrementally and emits numbered raw chunks plus `chunks.ndjson` and a
small terminal `manifest.json`. Individual chunk bytes, the exact index bytes and
complete source bytes have separate hashes. The index is streamed rather than
retained as a capture-sized Python array. The current upper bound is one million
chunks and a configurable disk budget; it is not an unlimited storage promise.

The new destination must not exist. Chunk files are completed/synced before the
terminal manifest is published. An interruption can leave an incomplete directory;
absence of the terminal manifest prevents a completed-archive interpretation.
This is a recoverable evidence layout, not a transactional filesystem or guaranteed
cross-platform power-failure durability claim. Parent namespaces must be trusted.

```python
from tools.product.history import archive, verify_archive, replay_archive
archive('sample.pcap', '/new/source-archive')
proof = verify_archive('/new/source-archive')
with open('/new/replayed.pcap', 'xb') as output:
    replay_archive('/new/source-archive', output)
```

Replay verifies the archive, then rechecks chunks as it writes. Generic output may
be partial on I/O failure and must be discarded; no source bytes are repaired.
Source identity is not capture authorship, chain of custody or semantic correctness.

## Disk-backed interval reconstruction

`StreamStore` keeps an indexed set of source-byte intervals keyed by an explicit
analysis hypothesis and direction. Its caller supplies unwrapped sequence positions,
source offsets and an independently justified scope; the store does not guess TCP
connection generations. It checks source identity, detects overlap alternatives,
retains conflicts and emits bounded pieces or gaps according to an explicit policy.

Read `tools/product/history.py` for exact methods and `HistoryTests` for executable
usage. Do not identify an upstream bounded window as a complete endpoint connection
merely because its payload was inserted into this store. This vertical slice is
useful for retained-history hypotheses, but automatic packet→TCP generation→disk
state→protocol reconstruction across all cuts remains unfinished.

Memory/disk counters constrain selected stored data and query work, not every
allocator page, journal byte or OS cache. Run untrusted workloads in OS resource
limits and qualify temporary disk amplification, crash recovery and actual peak
RSS before exposing this as an upload service or advertising 500 GB support.
