# Local investigation workbench

## Implementation, not a screenshot-only prototype

`tools.desktop.server` owns selected capture/workspace roots and a small loopback
API. `tools.desktop.worker` runs analysis in a child process and incrementally
projects checked NDJSON events into SQLite. `desktop/web/` uses dependency-free
browser modules, bounded pagination and row virtualization. No npm installation
or build-time network request is needed to run this implementation.

Start it from the integrated repository (or package `code/` for reference inspection):

```sh
python -m tools.desktop.server --capture-root /captures --workspace /separate/workspace --engine /repo/product/target/release/pcap-product
```

Omit `--engine` to make only explicitly labeled Python container inspection
available. That mode supplies record/packet/clock inspection, not Rust protocol
analysis. Native failure never silently falls back. Add `--tshark /trusted/tshark`
only to authorize that local executable as a separately attributed comparison tool.

## Views and behavior

Overview shows source/run identity, counts, binding status and scope. Packets/events
use 200-row maximum pages with a small virtualized DOM viewport. Flow, protocol,
transaction and issue views query the same structured event store. The issue view
starts at incomplete status; use the status filter to inspect ambiguous, rejected
or unsupported observations separately.

An event opens the evidence inspector: contributing frames, selected spans,
reconstructed hashes, parent/child relations and bounded raw packet hex. The packet
hash is checked before showing bytes. Reverse pivots return events with intersecting
selected source spans. They do not pretend to prove all downstream causal
relationships; uninstrumented or truncated relations remain unavailable.

Timeline aggregation is explicitly a bounded first-10,000-packet page with exact
integer time arithmetic and an unknown-time count. It is not a full-capture
histogram or proof of interactive performance on a billion packets. The backend
has a query instruction budget; an expensive query may return a resource error.

Research permits independently attributed local runs/imports, side-by-side semantic
field comparisons, first-divergence inspection, case search/audit and raw-witness ZIP
export. Importing an interpretation does not execute its declared command. A raw
capture export requires explicit acknowledgment. Catalog entries remain pending
qualification instead of being displayed as passing conformance.

## Local security boundary

- Bind only to 127.0.0.1. The printed URL carries a random fragment token. API
  requests require a bearer token and validated Host/Origin. Static assets use
  restrictive CSP, no-store, nosniff, no-referrer and no framing.
- The server starts with explicit capture/workspace roots. Browser requests cannot
  provide arbitrary local executables, shell commands or capture paths outside that
  root. Symlink traversal is rejected. Original captures are not mutated.
- One active analysis job per workspace; subprocess output and request/response
  sizes are bounded. Cancellation targets the owned worker group on POSIX.
  Windows cancellation behavior still requires platform validation.
- The workspace is exclusive via `.owner.lock`. An abandoned lock is not silently
  removed. Confirm its owning process has exited and no server uses the workspace
  before deliberately removing it. Interrupted jobs retain partial/provisional state.
- The SQLite projection is rebuildable, not the evidence authority. Completing an
  event hash chain and checking source bytes does not authenticate the producer or
  establish semantic replay. These statuses remain separate in the UI.

This is a trusted single-local-user workbench, not an Internet-facing multi-tenant
service or arbitrary plugin sandbox. Protect local workspaces and exported captures
as sensitive data. Do not place the token in a public issue or enable remote access.

## Testing boundary

`tools/tests/test_desktop_http.py` uses real loopback HTTP, real worker processes,
SQLite, source-byte inspection and bundle exports. `model.test.mjs` tests exact
integer/time handling and virtual-range mathematics. `gui_render_smoke.py` renders
recorded real backend responses offline in Chromium, using an in-memory transport;
it is explicitly not a live browser-to-server test. `gui_smoke.py` is supplied for
that separate real-browser gate. The authoring host's managed browser policy blocked
loopback navigation, so that gate remains BLOCKED rather than bypassing policy.

No Tauri wrapper, signed installer, native file association, full platform keyboard/
accessibility certification, or shipped Windows/Linux desktop package is claimed.
