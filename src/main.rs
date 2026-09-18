#![forbid(unsafe_code)]
use pcap_evidence::capture::ParseMode;
use pcap_evidence::engine::{self, Config};
use pcap_evidence::index::{Index, VerifiedIndex};
use pcap_evidence::json::Json;
use pcap_evidence::publish::{read_bounded, write_new};
use pcap_evidence::tcp::OverlapPolicy;
use pcap_evidence::wire::ChecksumPolicy;
use pcap_evidence::{correlate, report, sha256, Error, ErrorCode, Result};
use std::collections::BTreeSet;
use std::io::Write;
use std::path::{Path, PathBuf};
const HELP: &str = r#"pcap-evidence 0.1.0 — offline capture evidence, not an attack detector

USAGE
  pcap-evidence inspect CAPTURE [OPTIONS]
  pcap-evidence analyze CAPTURE [OPTIONS]
  pcap-evidence index CAPTURE -o CAPTURE.pcidx [--max-input-mib N]
  pcap-evidence verify-index CAPTURE --index CAPTURE.pcidx
  pcap-evidence packet CAPTURE --index CAPTURE.pcidx --frame N [-o packet.json]

OPTIONS
  -o, --output PATH       Atomically create a NEW file; never overwrite.
  --evidence             Preserve readable length/time contradictions with warnings.
  --include-payload      Include sensitive packet/stream bytes in JSON (never DSB keys).
  --max-input-mib N      Input bound (default 256 MiB; not an aggregate RAM guarantee).
  --labels PATH          analyze: external v1 TSV attempt labels; matches are candidates.
  --overlap POLICY       analyze: reject (default), first, last; not OS emulation.
  --strict-checksums     analyze: reject invalid checksums (offloads can cause artifacts).
  --require-clean        analyze: exit 4 if any diagnosed degradation; still emit report.
  --dnp3-port N          analyze: repeat or CSV; first replaces default 20000.
  --modbus-port N        analyze: repeat or CSV; first replaces default 502.
  --index PATH           verify-index/packet: fully verify source + sidecar semantics.
  --frame N              packet: 1-based packet ordinal, NOT PCAPNG block ordinal.
  -h, --help             Print help.
  --version              Print version.

EXIT: 0 completed; 2 usage/labels; 3 I/O/publication; 4 malformed/unsupported/degraded.
JSON stdout may be piped; source files are never rewritten. Index verification scans
once; repeated packet access through the library's VerifiedIndex is then indexed.
"#;
struct Args {
    command: String,
    input: PathBuf,
    output: Option<PathBuf>,
    index: Option<PathBuf>,
    frame: Option<u64>,
    labels: Option<PathBuf>,
    include_payload: bool,
    require_clean: bool,
    config: Config,
}
fn usage(detail: &str) -> Error {
    Error::new(ErrorCode::Usage, 0, "arguments", detail)
}
fn parse_args(args: Vec<String>) -> Result<Args> {
    if args.len() < 2 {
        return Err(usage("expected command and capture path; use --help"));
    }
    let command = args[0].clone();
    if !["inspect", "analyze", "index", "verify-index", "packet"].contains(&command.as_str()) {
        return Err(usage("unknown command"));
    }
    let mut out = Args {
        command,
        input: args[1].clone().into(),
        output: None,
        index: None,
        frame: None,
        labels: None,
        include_payload: false,
        require_clean: false,
        config: Config::default(),
    };
    let mut i = 2;
    let mut seen = BTreeSet::new();
    while i < args.len() {
        let flag = match args[i].as_str() {
            "-o" => "--output",
            other => other,
        };
        let first_occurrence = seen.insert(flag.to_owned());
        if !first_occurrence && !["--dnp3-port", "--modbus-port"].contains(&flag) {
            return Err(usage("duplicate option"));
        }
        let needs_value = [
            "--output",
            "--index",
            "--frame",
            "--labels",
            "--max-input-mib",
            "--overlap",
            "--dnp3-port",
            "--modbus-port",
        ]
        .contains(&flag);
        let value = if needs_value {
            i += 1;
            args.get(i)
                .ok_or_else(|| usage("option requires a value"))?
                .as_str()
        } else {
            ""
        };
        if [
            "--labels",
            "--overlap",
            "--strict-checksums",
            "--require-clean",
            "--dnp3-port",
            "--modbus-port",
        ]
        .contains(&flag)
            && out.command != "analyze"
        {
            return Err(usage("analysis option used with a different command"));
        }
        if ["--index", "--frame"].contains(&flag)
            && !["verify-index", "packet"].contains(&out.command.as_str())
        {
            return Err(usage("index lookup option used with a different command"));
        }
        match flag {
            "--output" => out.output = Some(value.into()),
            "--index" => out.index = Some(value.into()),
            "--frame" => {
                out.frame = Some(value.parse().map_err(|_| usage("invalid frame ordinal"))?)
            }
            "--labels" => out.labels = Some(value.into()),
            "--include-payload" => out.include_payload = true,
            "--evidence" => {
                if !["inspect", "analyze"].contains(&out.command.as_str()) {
                    return Err(usage("sidecars require strict parsing"));
                }
                out.config.parse_mode = ParseMode::Evidence;
            }
            "--max-input-mib" => {
                let mib: usize = value
                    .parse()
                    .map_err(|_| usage("invalid input MiB budget"))?;
                out.config.limits.max_input_bytes = mib
                    .checked_mul(1024 * 1024)
                    .filter(|n| *n > 0)
                    .ok_or_else(|| usage("input budget overflow/zero"))?;
            }
            "--overlap" => {
                out.config.overlap_policy = match value {
                    "reject" => OverlapPolicy::RejectConflict,
                    "first" => OverlapPolicy::FirstObserved,
                    "last" => OverlapPolicy::LastObserved,
                    _ => return Err(usage("overlap must be reject, first or last")),
                }
            }
            "--strict-checksums" => out.config.checksum_policy = ChecksumPolicy::RequireValid,
            "--require-clean" => out.require_clean = true,
            "--dnp3-port" => {
                pcap_evidence::cli_ports::extend_ports(
                    &mut out.config.dnp3_ports,
                    value,
                    first_occurrence,
                )?;
            }
            "--modbus-port" => {
                pcap_evidence::cli_ports::extend_ports(
                    &mut out.config.modbus_ports,
                    value,
                    first_occurrence,
                )?;
            }
            _ => return Err(usage("unknown option")),
        }
        i += 1;
    }
    if out.command == "index" && out.output.is_none() {
        return Err(usage(
            "index requires -o; binary output is not sent to stdout",
        ));
    }
    if ["verify-index", "packet"].contains(&out.command.as_str()) && out.index.is_none() {
        return Err(usage("--index is required"));
    }
    if out.command == "packet" && out.frame.is_none() {
        return Err(usage("--frame is required"));
    }
    if out.command == "verify-index" && out.frame.is_some() {
        return Err(usage("verify-index does not accept --frame"));
    }
    out.config.validate()?;
    Ok(out)
}
fn emit(value: Json, path: Option<&Path>) -> Result<()> {
    // Metadata representation overhead is bounded separately from input size.
    let bytes = value.encode_bounded_line(512 * 1024 * 1024)?.into_bytes();
    if let Some(path) = path {
        write_new(path, &bytes)?;
    } else {
        std::io::stdout().lock().write_all(&bytes)?;
    }
    Ok(())
}
fn run(args: Args) -> Result<i32> {
    let input = read_bounded(&args.input, args.config.limits.max_input_bytes)?;
    match args.command.as_str() {
        "inspect" => emit(
            report::inspect(
                &input,
                args.config.limits,
                args.config.parse_mode,
                args.include_payload,
            )?,
            args.output.as_deref(),
        )?,
        "analyze" => {
            let mut analysis = engine::analyze(&input, args.config)?;
            if let Some(path) = args.labels {
                let raw = read_bounded(&path, 16 * 1024 * 1024)?;
                let text = std::str::from_utf8(&raw).map_err(|_| {
                    Error::new(ErrorCode::InvalidLabel, 0, "labels", "UTF-8 required")
                })?;
                correlate::apply_labels(&mut analysis, text)?;
            }
            let degraded = analysis.has_diagnostics();
            let mut value = report::analysis(&analysis, args.include_payload);
            if let Json::Object(ref mut fields) = value {
                fields.push((
                    "protocol_detection",
                    pcap_evidence::detection::analysis_json(&analysis)?,
                ));
            }
            emit(value, args.output.as_deref())?;
            if args.require_clean && degraded {
                return Ok(4);
            }
        }
        "index" => {
            let index = Index::build(&input, args.config.limits)?;
            write_new(
                args.output
                    .as_deref()
                    .ok_or_else(|| usage("missing output"))?,
                &index.encode()?,
            )?;
        }
        "verify-index" | "packet" => {
            let max_index = args
                .config
                .limits
                .max_records
                .checked_mul(64)
                .and_then(|n| n.checked_add(88))
                .ok_or_else(|| usage("index limit overflow"))?;
            let bytes = read_bounded(
                args.index
                    .as_deref()
                    .ok_or_else(|| usage("missing index"))?,
                max_index,
            )?;
            let index = VerifiedIndex::load(&input, &bytes, args.config.limits)?;
            let value = if args.command == "packet" {
                let frame = args.frame.ok_or_else(|| usage("missing frame"))?;
                let data = index.packet(frame)?;
                Json::object([
                    ("schema", "pcap-evidence.packet.v1".into()),
                    (
                        "capture_sha256",
                        sha256::hex(&sha256::digest(&input)).into(),
                    ),
                    ("frame", frame.into()),
                    ("length", data.len().into()),
                    ("packet_sha256", sha256::hex(&sha256::digest(data)).into()),
                    ("packet_hex", sha256::hex(data).into()),
                ])
            } else {
                Json::object([
                    ("schema", "pcap-evidence.index-verification.v1".into()),
                    ("verified", true.into()),
                    (
                        "capture_sha256",
                        sha256::hex(&index.index().source_sha256()).into(),
                    ),
                    ("packets", index.index().entries().len().into()),
                ])
            };
            emit(value, args.output.as_deref())?;
        }
        _ => return Err(usage("unknown command")),
    }
    Ok(0)
}
fn main() {
    let args: Vec<String> = match std::env::args_os()
        .skip(1)
        .map(|s| s.into_string())
        .collect()
    {
        Ok(args) => args,
        Err(_) => {
            eprintln!("usage: command-line arguments must be UTF-8");
            std::process::exit(2);
        }
    };
    if args.len() == 1 && ["--help", "-h"].contains(&args[0].as_str()) {
        print!("{HELP}");
        return;
    }
    if args.len() == 1 && args[0] == "--version" {
        println!("pcap-evidence {}", env!("CARGO_PKG_VERSION"));
        return;
    }
    let code = match parse_args(args).and_then(run) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("{}", Json::object([("error", report::error(&e))]).encode());
            match e.code {
                ErrorCode::Usage | ErrorCode::InvalidLabel => 2,
                ErrorCode::Io | ErrorCode::OutputExists => 3,
                _ => 4,
            }
        }
    };
    std::process::exit(code);
}
