# Optional C ABI and Linux acquisition boundaries

## C ABI v1 — separate unsafe boundary

The `product/ffi/` workspace produces `pcap_evidence_ffi` as a static/dynamic library.
It depends on the existing safe root analyzer, not on external parsers. The checked-in
header defines explicit statuses, opaque numeric handles and these operations:
create, feed, analyze, output_size, copy_output, destroy, abi_version.

Each handle has bounded input/output (at most 64 MiB each), is one-shot after analyze,
and never returns a borrowed Rust pointer. At most eight handles are retained. Feed
copies caller bytes. Output copies into caller-owned storage; the reported length
is exact and output is not NUL terminated. Buffer-too-small leaves destination bytes
untouched. Failed analysis does not expose a successful empty result. Destroy
invalidates the numeric handle; handles are not reused. Calls are serialized through
a process-wide mutex, including analysis. No callbacks occur under that lock.

The caller must supply valid aligned writable/readable allocations of the stated
length. Null checks cannot prove arbitrary non-null pointers valid. `written` and
output buffers must not alias in ways that violate their documented use. Rust
panic catching prevents ordinary unwinding across this boundary, not allocator
abort, invalid-pointer UB, process termination or every OS failure. This interface
is not a sandbox for untrusted native callers.

Linux build/link/run:

```sh
cargo build --manifest-path product/ffi/Cargo.toml --release --locked --offline
cc -std=c11 -Wall -Wextra -Werror product/ffi/harness.c \
  -Lproduct/ffi/target/release -lpcap_evidence_ffi \
  -Wl,-rpath,"$(pwd)/product/ffi/target/release" -o /new/ffi-client
/new/ffi-client
```

The harness exercises 100 create/feed/analyze/copy/destroy cycles and short buffers.
The authoring host only compiled the C translation unit. Native Rust, linking and
runtime cycles were not performed. Windows/MSVC and other target ABIs need their own
native link/run gate, not an inference from the header compiling elsewhere.

## Linux AF_PACKET acquisition — opt-in standalone C adapter

This implementation is deliberately isolated from the safe parser crate:

```sh
cc -std=c11 -O2 -Wall -Wextra -Werror product/live/capture_linux.c -o /new/pcap-capture
/new/pcap-capture --allow-live-capture --interface eth0 --output /new/capture.pcap --max-packets 10000 --max-bytes 104857600
```

Only an explicitly authorized local operator should invoke real capture. The program
never escalates privileges. Insufficient CAP_NET_RAW/socket permission fails closed.
It verifies an Ethernet interface, binds AF_PACKET, requests kernel SO_TIMESTAMPNS,
uses a bounded receive buffer, records original/captured sizes and writes nanosecond
classic PCAP. SIGINT/SIGTERM closes capture; packet/byte limits and kernel drop-counter
availability are reported. The optional `--ethertype` is a decimal software filter,
not a full BPF/display-filter language; VLAN-inner EtherTypes are not inferred.

There is no packet injection, telemetry, automatic permission grant or non-Linux
implementation. Missing/invalid receive timestamps fail rather than inventing time.
Kernel acquisition timestamps are wall-clock observations at capture time; replay
still uses only saved capture clocks. Slow output can cause kernel packet drops;
there is no claim of lossless live backpressure. Drop statistics are observations,
not proof of completeness.

Output is a new file published through a temporary file and hard link in a trusted
stable parent. Disk-limit/I/O failures discard this temporary capture rather than
publish a complete-looking run. This standalone adapter does not yet stream typed
Rust events directly from a NIC or provide all requested live-profile features.

The deterministic denial gate compiles with `-DPCAP_TEST_DENY_SOCKET`, supplies
`--allow-live-capture --interface test0 --output /new/must-not-exist.pcap`, and must
exit 3 without creating output. That gate was executed. No actual NIC capture,
privileged operation or Rust/C live integration was performed on the authoring host.
