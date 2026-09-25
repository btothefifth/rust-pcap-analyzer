# Independent `pcap-parser` oracle

This optional binary uses `pcap-parser = 0.17.0` and **does not depend on the root
parser**. It emits packet ordinals and captured/original lengths for classic PCAP,
PCAPNG Enhanced Packet Blocks and Simple Packet Blocks. It does not normalize raw
clocks or decode protocols. Other PCAPNG blocks are not claimed equivalent; a
count mismatch on an unsupported old packet-block variant must be adjudicated.

The API was checked against upstream reader/trait documentation. The binary has
not been compiled on the authoring host. Its dependency lock must be generated and
reviewed on the integration worker; do not claim locked reproducibility beforehand.

```sh
# Explicit dependency acquisition/lock approval step, outside root runtime builds:
cargo generate-lockfile --manifest-path tools/pcap-parser-oracle/Cargo.toml
cargo build --manifest-path tools/pcap-parser-oracle/Cargo.toml --locked --release
python tools/evidence_tool.py differential capture.pcap receipts/differential-01 \
  --binary streaming/target/release/pcap-stream \
  --pcap-parser tools/pcap-parser-oracle/target/release/pcap-parser-independent-oracle \
  --require pcap-stream,tshark,pcap-parser
```

Upstream API reference: https://github.com/rusticata/pcap-parser/blob/master/src/traits.rs
Runtime dependency/license review remains required for this optional tool.
