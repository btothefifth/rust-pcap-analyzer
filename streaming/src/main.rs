#![forbid(unsafe_code)]
use pcap_evidence::{
    capture::ParseMode, cli_ports::extend_ports, json::Json, tcp::OverlapPolicy,
    wire::ChecksumPolicy,
};
use pcap_evidence_stream::{
    analyze_reader, Error, ErrorCode, NdjsonSink, Registry, Result, StreamConfig,
};
use std::{
    collections::BTreeSet,
    fs::{self, File, OpenOptions},
    io::{self, BufReader, BufWriter, Read, Write},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
const HELP: &str = r#"pcap-stream 0.1.0 — incremental evidence, bounded reconstruction windows

pcap-stream analyze CAPTURE|- [--output NEW.ndjson] [--run-id ID] [OPTIONS]

  --active-flows N          Maximum active tuple keys (default 256).
  --active-bytes N          Retained TCP payload across keys (default 33554432).
  --window-bytes N          Retained TCP bytes per window (default 262144).
  --window-packets N        Source packet references per window (default 2048).
  --idle-frames N           Idle eviction in capture packet ordinals.
  --idle-ns N               Idle eviction with exact timestamps.
  --source-bytes N          Source read limit, independent of retained-state limits.
  --event-bytes N           Maximum encoded event line size.
  --plugin-bytes N          Per-analyzer buffer/message limit.
  --plugin-events N         Emitted messages/issues per reconstruction window.
  --probe-bytes N           Maximum content prefix inspected by detectors.
  --tunnel-contexts N       Bounded independent fragment namespaces.
  --tunnel-depth N          GRE/VXLAN/Geneve nesting limit.
  --fragment-bytes N        Retained fragment payload budget across namespaces.
  --dnp3-port N[,N...]      First occurrence replaces defaults; repeats append.
  --modbus-port N[,N...]    Same semantics in both CLIs and the library.
  --allow-port-hints        Fall back to configured industrial ports if no probe matches.
  --overlap reject|first|last
  --strict-checksums
  --evidence               Preserve structurally readable container anomalies.
  --include-payload        Include reconstructed TCP bytes. Secrets blocks stay redacted.
  --require-clean          Exit 4 after publishing if degradation was reported.

Advanced replay limits:
  --block-bytes --packet-bytes --interfaces --options --stream-span
  --fragment-sets --fragments-per-set --fragment-lifetime
  --native-messages --application-bytes --correlation-checks --detectors

stdout is one hash-chained event per line. Source binding completes only at EOF.
Output files use no-clobber publication; errors do not publish a successful file.
A window ID is NOT proof of a distinct TCP connection. State does not cross cuts.
Exit: 0 completed; 2 usage; 3 I/O; 4 malformed/limited/degraded.
"#;
struct Args {
    input: String,
    output: Option<PathBuf>,
    run_id: String,
    config: StreamConfig,
    clean: bool,
}
fn usage(detail: impl Into<String>) -> Error {
    Error::new(ErrorCode::Usage, 0, "arguments", detail)
}
fn number<T: std::str::FromStr>(s: &str) -> Result<T> {
    s.parse().map_err(|_| usage("invalid numeric argument"))
}
fn parse(args: &[String]) -> Result<Args> {
    if args.len() < 2 || args[0] != "analyze" {
        return Err(usage("expected analyze CAPTURE; use --help"));
    }
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| usage("system clock predates epoch; pass a stable environment"))?
        .as_nanos();
    let mut out = Args {
        input: args[1].clone(),
        output: None,
        run_id: format!("run-{}-{nonce}", std::process::id()),
        config: StreamConfig::default(),
        clean: false,
    };
    let mut seen = BTreeSet::new();
    let mut i = 2;
    while i < args.len() {
        let flag = if args[i] == "-o" {
            "--output"
        } else {
            args[i].as_str()
        };
        let first = seen.insert(flag.to_owned());
        if !first && !["--dnp3-port", "--modbus-port"].contains(&flag) {
            return Err(usage("duplicate option"));
        }
        let switch = [
            "--evidence",
            "--strict-checksums",
            "--include-payload",
            "--allow-port-hints",
            "--require-clean",
        ]
        .contains(&flag);
        let value = if switch {
            ""
        } else {
            i += 1;
            args.get(i)
                .ok_or_else(|| usage("missing option value"))?
                .as_str()
        };
        let c = &mut out.config;
        match flag {
            "--output" => out.output = Some(value.into()),
            "--run-id" => out.run_id = value.into(),
            "--active-flows" => c.max_active_keys = number(value)?,
            "--active-bytes" => c.max_active_payload = number(value)?,
            "--window-bytes" => c.window_payload = number(value)?,
            "--window-packets" => c.window_packets = number(value)?,
            "--idle-frames" => c.idle_frames = number(value)?,
            "--idle-ns" => c.base.idle_timeout_ns = number(value)?,
            "--source-bytes" => c.max_source_bytes = number(value)?,
            "--event-bytes" => c.max_event_bytes = number(value)?,
            "--plugin-bytes" => c.max_plugin_bytes = number(value)?,
            "--plugin-events" => c.max_plugin_events = number(value)?,
            "--probe-bytes" => c.max_probe_bytes = number(value)?,
            "--detectors" => c.max_detectors = number(value)?,
            "--tunnel-contexts" => c.max_tunnel_contexts = number(value)?,
            "--tunnel-depth" => c.max_tunnel_depth = number(value)?,
            "--fragment-bytes" => c.fragment_payload = number(value)?,
            "--block-bytes" => c.base.limits.max_block_bytes = number(value)?,
            "--packet-bytes" => c.base.limits.max_packet_bytes = number(value)?,
            "--interfaces" => c.base.limits.max_interfaces = number(value)?,
            "--options" => c.base.limits.max_options = number(value)?,
            "--stream-span" => c.base.limits.max_stream_span = number(value)?,
            "--fragment-sets" => c.base.limits.max_fragment_sets = number(value)?,
            "--fragments-per-set" => c.base.limits.max_fragments_per_set = number(value)?,
            "--fragment-lifetime" => c.base.limits.fragment_frame_lifetime = number(value)?,
            "--native-messages" => c.base.limits.max_protocol_messages = number(value)?,
            "--application-bytes" => c.base.limits.max_application_bytes = number(value)?,
            "--correlation-checks" => c.base.limits.max_correlation_checks = number(value)?,
            "--dnp3-port" => extend_ports(&mut c.base.dnp3_ports, value, first)?,
            "--modbus-port" => extend_ports(&mut c.base.modbus_ports, value, first)?,
            "--evidence" => c.base.parse_mode = ParseMode::Evidence,
            "--strict-checksums" => c.base.checksum_policy = ChecksumPolicy::RequireValid,
            "--include-payload" => c.include_payload = true,
            "--allow-port-hints" => c.allow_port_hints = true,
            "--require-clean" => out.clean = true,
            "--overlap" => {
                c.base.overlap_policy = match value {
                    "reject" => OverlapPolicy::RejectConflict,
                    "first" => OverlapPolicy::FirstObserved,
                    "last" => OverlapPolicy::LastObserved,
                    _ => return Err(usage("invalid overlap policy")),
                }
            }
            _ => return Err(usage(format!("unknown option {flag}"))),
        }
        i += 1;
    }
    out.config.validate()?;
    Ok(out)
}
struct Temporary(PathBuf);
impl Drop for Temporary {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}
fn publish_output(
    input: Box<dyn Read>,
    a: &Args,
    registry: &Registry,
    path: &Path,
) -> Result<pcap_evidence_stream::Summary> {
    if path.exists() {
        return Err(Error::new(
            ErrorCode::OutputExists,
            0,
            "output",
            "destination already exists",
        ));
    }
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| usage("clock before epoch"))?
        .as_nanos();
    let temp_path = parent.join(format!(".pcap-events-{}-{stamp}.tmp", std::process::id()));
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let file = opts.open(&temp_path)?;
    // Only own cleanup after create_new succeeds: a collision is not ours to delete.
    let temp = Temporary(temp_path);
    let mut sink = NdjsonSink::new(
        BufWriter::new(file),
        a.run_id.clone(),
        a.config.max_event_bytes,
    )?;
    let summary = analyze_reader(input, a.config.clone(), registry, &mut sink)?;
    let writer = sink.finish()?;
    let file = writer
        .into_inner()
        .map_err(|e| Error::from(e.into_error()))?;
    file.sync_all()?;
    drop(file);
    // Atomic no-replace publication in a trusted, stable parent directory.
    fs::hard_link(&temp.0, path).map_err(|e| {
        if e.kind() == io::ErrorKind::AlreadyExists {
            Error::new(
                ErrorCode::OutputExists,
                0,
                "output",
                "destination appeared during publication",
            )
        } else {
            Error::from(e)
        }
    })?;
    fs::remove_file(&temp.0)?;
    #[cfg(unix)]
    {
        File::open(parent)?.sync_all()?;
    }
    Ok(summary)
}
fn run(a: Args) -> Result<i32> {
    let registry = Registry::builtins(&a.config)?;
    let input: Box<dyn Read> = if a.input == "-" {
        Box::new(io::stdin())
    } else {
        Box::new(BufReader::with_capacity(1024 * 1024, File::open(&a.input)?))
    };
    let result = if let Some(path) = &a.output {
        publish_output(input, &a, &registry, path)?
    } else {
        let stdout = io::stdout();
        let mut sink = NdjsonSink::new(
            BufWriter::new(stdout.lock()),
            a.run_id.clone(),
            a.config.max_event_bytes,
        )?;
        let result = analyze_reader(input, a.config.clone(), &registry, &mut sink)?;
        sink.finish()?.flush()?;
        result
    };
    Ok(if a.clean && result.degraded_events > 0 {
        4
    } else {
        0
    })
}
fn main() {
    let args: Vec<String> = match std::env::args_os()
        .skip(1)
        .map(|x| x.into_string())
        .collect()
    {
        Ok(v) => v,
        Err(_) => {
            eprintln!("arguments must be UTF-8");
            std::process::exit(2);
        }
    };
    if args.len() == 1 && ["--help", "-h"].contains(&args[0].as_str()) {
        print!("{HELP}");
        return;
    }
    if args.len() == 1 && args[0] == "--version" {
        println!("pcap-stream {}", env!("CARGO_PKG_VERSION"));
        return;
    }
    let code = match parse(&args).and_then(run) {
        Ok(n) => n,
        Err(e) => {
            eprintln!(
                "{}",
                Json::object([("error", e.to_string().into())]).encode()
            );
            match e.code {
                ErrorCode::Usage | ErrorCode::InvalidLabel => 2,
                ErrorCode::Io | ErrorCode::OutputExists => 3,
                _ => 4,
            }
        }
    };
    std::process::exit(code);
}
