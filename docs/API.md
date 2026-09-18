# API and command-line guide

The examples below use the included API, not `pcap-parser` or libpcap APIs. They are
covered by the local native validation gate described in `VALIDATION.md`; platform-
specific and real-world qualification remain open.

## Borrowed container parsing

```rust
use pcap_evidence::capture::{CaptureIter, ParseMode};
use pcap_evidence::{Limits, Result};

fn inspect(bytes: &[u8]) -> Result<()> {
    for item in CaptureIter::new(bytes, Limits::default(), ParseMode::Strict)? {
        let record = item?;
        if let Some((meta, data)) = record.packet() {
            println!("frame={} interface={} bytes={} time={:?}",
                     meta.frame, meta.interface, data.len(), meta.timestamp);
        }
        // record.raw() preserves the entire original record/block.
        // record.offset() is the source byte offset.
    }
    Ok(())
}
```

`CaptureIter` borrows packet and raw-block bytes from its input. Section/interface
state and option metadata still need bookkeeping. A returned raw record is not an
owned packet and cannot outlive the input snapshot. Errors fuse the iterator.

## Streaming record reader

```rust
use std::fs::File;
use pcap_evidence::capture::{CaptureReader, ParseMode};
use pcap_evidence::{Limits, Result};

fn stream(path: &str) -> Result<()> {
    let input = File::open(path)?;
    let reader = CaptureReader::new(input, Limits::default(), ParseMode::Strict)?;
    for item in reader {
        let record = item?; // owns this record's bytes
        if let Some((meta, bytes)) = record.packet() {
            println!("{} {}", meta.frame, bytes.len());
        }
    }
    Ok(())
}
```

Short reads and interrupted reads are handled explicitly. The reader's configured
input/record/packet limits still apply; streaming does not disable budgets. It is
synchronous `std::io::Read`. There is no Tokio/mmap adapter advertised in this version.
The common incremental `Decoder` is the extension seam, not a duplicate parser.

## Full offline analysis and labels

```rust
use pcap_evidence::{correlate, engine::{analyze, Config}, report, Result};

fn analyze_json(bytes: &[u8], labels: Option<&str>) -> Result<String> {
    let mut analysis = analyze(bytes, Config::default())?;
    if let Some(tsv) = labels {
        correlate::apply_labels(&mut analysis, tsv)?;
    }
    report::analysis(&analysis, false).encode_bounded(64 * 1024 * 1024)
}
```

The engine consumes an immutable snapshot. It retains bounded reconstructed payload
and source spans. Reports are derived values, not authenticated declarations.
`has_diagnostics()` detects supported-path degradation; `false` does not prove the
capture includes every wire packet or that an attack was benign.

Configuration fields include limits, capture parse mode, overlap policy, checksum
policy, idle timeout in integer nanoseconds and explicit DNP3/Modbus port lists.
Protocol service-role configuration is not inferred from which side sent the SYN.

### Configured UDP DNP3 and advisory probes

When either endpoint of a decoded UDP datagram uses a configured DNP3 port,
`engine::analyze` creates one `datagram::DatagramAnalysis` entry. Its payload and
packet IDs retain the original source spans, and its DNP3 result is decoded with
fresh state for that datagram only. A UDP datagram is not treated as an ordered,
reliable stream: separate datagrams are never concatenated, retransmitted, or used
to complete one another. The JSON projection exposes these entries as
`udp_applications` and includes `reconstruction_scope` to make that boundary
machine-readable.

`protocol::ProbeRegistry` is an explicit extension point for bounded, read-only
prefix probes. Built-in DNP3 and Modbus probes report a structural observation and
their examined extent; they do not select the engine protocol, assign probability,
authenticate a peer, or authorize transaction correlation. A caller must provide a
contiguous prefix and inspect all returned observations when multiple probes match.

## Sidecar index

```rust
use pcap_evidence::index::{Index, VerifiedIndex};
use pcap_evidence::{Limits, Result};

fn first_packet(bytes: &[u8]) -> Result<Vec<u8>> {
    let sidecar = Index::build(bytes, Limits::default())?.encode()?;
    let verified = VerifiedIndex::load(bytes, &sidecar, Limits::default())?;
    Ok(verified.packet(1)?.to_vec())
}
```

Build/load scans source bytes. Load checks the sidecar structure and hashes, then
reconstructs canonical metadata from the exact source borrow. Only after that gate
can repeated `packet(frame)` accesses be direct indexed slices. `time_range(start_ns,
end_ns)` scans entries without assuming capture order is timestamp order; missing or
inexact times appear in `unresolved_frames` rather than disappearing.

## Writers

```rust
use pcap_evidence::capture::Endian;
use pcap_evidence::time::{Resolution, Timestamp};
use pcap_evidence::writer::PcapNgWriter;
use pcap_evidence::{Limits, Result};

fn wrap_packet(packet: &[u8]) -> Result<Vec<u8>> {
    let mut writer = PcapNgWriter::new(Vec::new(), Endian::Little, Limits::default())?;
    let interface = writer.interface(1, 65535, Resolution::Decimal(9), 0)?;
    let original = u32::try_from(packet.len())
        .map_err(|_| pcap_evidence::Error::limit("packet_bytes"))?;
    writer.packet(interface,
        Timestamp { ticks: 1_000_000_000, resolution: Resolution::Decimal(9), offset_seconds: 0 },
        original, packet)?;
    writer.finish()
}
```

This writer records bytes with caller-declared link type; it does not validate that
those bytes actually encode an Ethernet packet. Classical `PcapWriter` requires an
exactly representable timestamp; it refuses implicit sub-microsecond loss.
`copy_exact` validates an entire source before archival byte copying. It is not a
semantic edit operation that transplants do-not-copy custom extensions.

A generic `Write` failure can leave a partial output. After that failure, discard the
writer and the incomplete result. Prevalidation rejection occurs before the write
and permits a subsequent valid packet. Use `publish::write_new` to create a new
filesystem result without clobbering an existing output.

## CLI options and behavior

Use `--help` for the exact schema. Paths and arguments must be UTF-8 in the CLI;
library callers can use normal Rust path/read APIs. Flags with values accept one
occurrence. `--dnp3-port` and `--modbus-port` replace their respective default port;
use the library config for lists. No environment variable silently changes analysis.

The external label format is strict UTF-8 TSV with this header (tab separators):

```text
attempt_id	start_ns	end_ns	src_ip	src_port	dst_ip	dst_port	transport
```

Each row has a distinct ID, signed integer nanosecond start/end with `start <= end`,
exact IP addresses and ports, and `tcp` or `udp`. Bounds are inclusive; matching is
bidirectional. Wildcards, duplicate IDs, invented epoch defaults and float timestamps
are not accepted. `tests/fixtures/attempts.tsv` is an executable example.

Exit codes: **0** completed; **2** usage/label error; **3** I/O/publication failure;
**4** malformed/unsupported operation or `--require-clean` diagnostic result.
For `--require-clean`, the analysis report is still emitted before exit 4. An ordinary
`analyze` may complete with nonempty diagnostics and exit 0; consumers must inspect
report status, not infer clean evidence from successful process exit.

## JSON representation

Report schemas are explicitly named `pcap-evidence.*.v1`. Exact timestamps and large
signed offsets are serialized as decimal strings; do not round them through JSON
floating-point numbers. Packet ordinal and record offset are distinct. Stream and
protocol byte objects carry length, digest and source spans; payload hex is opt-in
except the explicit `packet` extraction command.

Every provenance span names the original packet ID, a byte interval in the derived
object, and a starting byte offset **inside the captured packet**, not inside its
PCAP record. DNP3 CRC removal and reconstruction preserve that distinction.
`check_cli.py` reconstructs these objects from source packet slices and checks their
hashes independently. Correlation rows are named candidates, with reasons for orphan,
ambiguous, incomplete, unsupported or missing-time states.
