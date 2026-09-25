# History state fuzzing (development only)

`state_transitions` drives forward/reverse SYN/ACK/FIN/RST inputs, sequence aliases,
opaque payloads, capture-time reversals, generation budgets and deterministic state
serialization. It checks repeatability and failure atomicity, not endpoint truth.
Only this isolated workspace depends on libfuzzer-sys. It is not part of runtime
builds. Dependencies must be provisioned explicitly on a prepared POSIX fuzz worker.

From this directory, after trusted tool provisioning:

```sh
CARGO_NET_OFFLINE=true cargo +nightly fuzz run state_transitions -- -max_total_time=3600 -timeout=10 -rss_limit_mb=2048
```

Record the compiler, source/config identities, seed hashes, duration, coverage,
findings and minimized reproductions. Preserve inherited packet/protocol fuzz
targets. No duration, coverage, crash freedom or security qualification is claimed
by the presence of this target. No sustained campaign was executed on the authoring host.
