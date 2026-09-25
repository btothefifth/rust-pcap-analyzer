# Evidence workbench UI

This is a working local browser UI, with real HTTP/query/worker source under
`tools/desktop/`. It is not a Tauri screenshot scaffold and requires no npm packages.

Run `python -m tools.desktop.server --capture-root /captures --workspace /workspace`
from the code/repository root. Open the printed loopback URL, including its token
fragment. Container-only reference inspection works without Cargo. Add an explicitly
built `--engine /path/to/pcap-product` for Rust protocol analysis.

Read `docs/product/GUI.md` for source/access boundaries, UI functions, test scope,
Windows qualifications and pending native packaging. Research imports do not execute
commands, and raw capture export requires explicit local consent.
