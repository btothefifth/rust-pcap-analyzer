# Rust TCP history candidate

Contract: `../docs/history/CONTRACT.md`. This crate adds disk-retained TCP evidence;
it is not a replacement for `pcap-stream` or complete unlimited application history.
It uses only local Rust path dependencies. No compiler or dependencies are installed
by these commands.

```sh
cargo fmt --manifest-path history/Cargo.toml --all
cargo test --manifest-path history/Cargo.toml --locked --offline --all-targets
cargo build --manifest-path history/Cargo.toml --locked --offline --release
history/target/release/pcap-history build capture.pcap history-new --max-disk-bytes 1073741824
history/target/release/pcap-history generations capture.pcap history-new
history/target/release/pcap-history range capture.pcap history-new GENERATION_HEX 0 0 256
history/target/release/pcap-history verify capture.pcap history-new replay-new
python -m tools.history_native capture.pcap history-new
```

On Windows the binary ends in `.exe`. Workspace names must not already exist.
`--nearest-frontier` is opt-in and labels epoch-selection assumptions. Recovery is
`pcap-history recover SOURCE OLD NEW [--allow-torn-tail]` and never edits OLD.
Unsealed workspaces are evidence of incomplete work, not successful history results.
