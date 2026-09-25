#![forbid(unsafe_code)]
use pcap_evidence::{capture::ParseMode, json::Json, tcp::OverlapPolicy, wire::ChecksumPolicy};
use pcap_evidence_product::{
    output::{ByteBudget, ProductSink},
    protocols::Protocol,
    registry, Error, ErrorCode, Result,
};
use pcap_evidence_stream::{analyze_reader, NdjsonSink, StreamConfig};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, BufReader, BufWriter, Write},
    path::{Path, PathBuf},
};
const HELP:&str="pcap-product 0.2.0\nUSAGE: pcap-product analyze CAPTURE [--profile it-light|it-full|ics-core|ics-full]\n [--format ndjson|tlv] [-o NEW_FILE] [--max-packets N] [--max-output-bytes N]\n [--run-id ID] [--window-bytes N] [--include-payload] [--evidence]\n [--strict-checksums] [--overlap reject|first|last] [--allow-port-hints]\n [--dnp3-port N[,N...]] [--modbus-port N[,N...]]\n pcap-product registry\n pcap-product --version\nOffline local files only. Full-history reconstruction is NOT claimed.\n";
struct Args {
    input: PathBuf,
    output: Option<PathBuf>,
    profile: String,
    format: String,
    run: String,
    max_packets: u64,
    max_output: u64,
    c: StreamConfig,
}
fn usage(s: &str) -> Error {
    Error::new(ErrorCode::Usage, 0, "arguments", s)
}
fn ports(value: &str, into: &mut Vec<u16>, first: bool) -> Result<()> {
    if first {
        into.clear();
    }
    for p in value.split(',') {
        let n = p.parse::<u16>().map_err(|_| usage("invalid port"))?;
        if !into.contains(&n) {
            into.push(n);
        }
    }
    into.sort_unstable();
    Ok(())
}
fn args(v: &[String]) -> Result<Args> {
    if v.len() < 2 || v[0] != "analyze" {
        return Err(usage("expected analyze CAPTURE; see --help"));
    }
    let mut a = Args {
        input: PathBuf::from(&v[1]),
        output: None,
        profile: "ics-full".into(),
        format: "ndjson".into(),
        run: "analysis".into(),
        max_packets: u64::MAX,
        max_output: 1u64 << 40,
        c: StreamConfig::default(),
    };
    a.c.max_detectors = 64;
    let mut i = 2;
    let mut seen = std::collections::BTreeSet::new();
    while i < v.len() {
        let flag = if v[i] == "-o" {
            "--output"
        } else {
            v[i].as_str()
        };
        let first = seen.insert(flag.to_owned());
        if !first && !matches!(flag, "--dnp3-port" | "--modbus-port") {
            return Err(usage("duplicate option"));
        }
        if matches!(
            flag,
            "--include-payload" | "--evidence" | "--strict-checksums" | "--allow-port-hints"
        ) {
            match flag {
                "--include-payload" => a.c.include_payload = true,
                "--evidence" => a.c.base.parse_mode = ParseMode::Evidence,
                "--strict-checksums" => a.c.base.checksum_policy = ChecksumPolicy::RequireValid,
                _ => a.c.allow_port_hints = true,
            }
            i += 1;
            continue;
        }
        i += 1;
        let value = v.get(i).ok_or_else(|| usage("missing option value"))?;
        match flag {
            "--output" => a.output = Some(value.into()),
            "--profile" => a.profile = value.clone(),
            "--format" => a.format = value.clone(),
            "--run-id" => a.run = value.clone(),
            "--max-packets" => {
                a.max_packets = value.parse().map_err(|_| usage("invalid packet budget"))?
            }
            "--max-output-bytes" => {
                a.max_output = value.parse().map_err(|_| usage("invalid output budget"))?
            }
            "--window-bytes" => {
                a.c.window_payload = value.parse().map_err(|_| usage("invalid window budget"))?
            }
            "--dnp3-port" => ports(value, &mut a.c.base.dnp3_ports, first)?,
            "--modbus-port" => ports(value, &mut a.c.base.modbus_ports, first)?,
            "--overlap" => {
                a.c.base.overlap_policy = match value.as_str() {
                    "reject" => OverlapPolicy::RejectConflict,
                    "first" => OverlapPolicy::FirstObserved,
                    "last" => OverlapPolicy::LastObserved,
                    _ => return Err(usage("invalid overlap policy")),
                }
            }
            _ => return Err(usage("unknown option")),
        }
        i += 1;
    }
    if !["ndjson", "tlv"].contains(&a.format.as_str()) || a.max_packets == 0 || a.max_output == 0 {
        return Err(usage("invalid format/budget"));
    }
    a.c.validate()?;
    Ok(a)
}
fn analyze(a: &Args, w: &mut dyn Write) -> Result<()> {
    let input = File::open(&a.input)?;
    if !input.metadata()?.is_file() {
        return Err(usage("capture must be a regular file"));
    }
    let source = File::open(&a.input)?;
    let r = registry::registry(&a.c, &a.profile)?;
    if a.format == "ndjson" {
        let mut sink = NdjsonSink::new(w, a.run.clone(), a.c.max_event_bytes)?;
        {
            let mut product = ProductSink {
                inner: &mut sink,
                source,
                packets: 0,
                maximum: a.max_packets,
                profile: a.profile.clone(),
                emitted: 0,
            };
            analyze_reader(BufReader::new(input), a.c.clone(), &r, &mut product)?;
        }
        sink.finish()?;
    } else {
        #[cfg(feature = "binary")]
        {
            let mut sink =
                pcap_evidence_product::tlv::TlvSink::new(w, a.run.clone(), a.c.max_event_bytes)?;
            {
                let mut product = ProductSink {
                    inner: &mut sink,
                    source,
                    packets: 0,
                    maximum: a.max_packets,
                    profile: a.profile.clone(),
                    emitted: 0,
                };
                analyze_reader(BufReader::new(input), a.c.clone(), &r, &mut product)?;
            }
            sink.finish()?;
        }
        #[cfg(not(feature = "binary"))]
        {
            return Err(usage("binary feature disabled"));
        }
    }
    Ok(())
}
fn publish(a: &Args, path: &Path) -> Result<()> {
    if path.exists() {
        return Err(Error::new(
            ErrorCode::OutputExists,
            0,
            "output",
            "destination exists",
        ));
    }
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut chosen = None;
    for n in 0..1000 {
        let temp = parent.join(format!(".pcap-product-{}-{n}.tmp", std::process::id()));
        match OpenOptions::new().write(true).create_new(true).open(&temp) {
            Ok(f) => {
                chosen = Some((temp, f));
                break;
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e.into()),
        }
    }
    let (temp, file) = chosen.ok_or_else(|| usage("unable to allocate output temporary file"))?;
    let result = (|| -> Result<()> {
        let mut writer = ByteBudget {
            inner: BufWriter::new(file),
            remaining: a.max_output,
        };
        analyze(a, &mut writer)?;
        writer.flush()?;
        writer.inner.get_ref().sync_all()?;
        fs::hard_link(&temp, path)?;
        Ok(())
    })();
    let _ = fs::remove_file(&temp);
    result
}
fn main() {
    let v: Vec<String> = match std::env::args_os()
        .skip(1)
        .map(|v| v.into_string())
        .collect()
    {
        Ok(v) => v,
        Err(_) => {
            eprintln!("command arguments must be valid UTF-8");
            std::process::exit(2);
        }
    };
    if v == ["--version"] {
        println!("pcap-product 0.2.0");
        return;
    }
    if v.is_empty() || v == ["--help"] || v == ["-h"] {
        print!("{HELP}");
        return;
    }
    if v == ["registry"] {
        println!(
            "{}",
            Json::array(Protocol::ALL.iter().map(|p| Json::object([
                ("protocol", p.name().into()),
                ("feature", p.feature().into()),
                ("enabled", p.compiled().into()),
                ("transport", p.transport().into()),
                ("support", "metadata-only".into())
            ])))
            .encode()
        );
        return;
    }
    let result = args(&v).and_then(|a| {
        if let Some(path) = &a.output {
            publish(&a, path)
        } else {
            let mut writer = ByteBudget {
                inner: BufWriter::new(io::stdout().lock()),
                remaining: a.max_output,
            };
            let result = analyze(&a, &mut writer);
            writer.flush()?;
            result
        }
    });
    if let Err(e) = result {
        eprintln!(
            "{}",
            Json::object([
                ("error", e.code.as_str().into()),
                ("field", e.field.into()),
                ("detail", e.detail.into())
            ])
            .encode()
        );
        std::process::exit(if e.code == ErrorCode::Usage {
            2
        } else if e.code == ErrorCode::Io || e.code == ErrorCode::OutputExists {
            3
        } else {
            4
        });
    }
}
