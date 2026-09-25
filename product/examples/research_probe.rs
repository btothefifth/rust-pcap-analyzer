//! Offline protocol research adapter. No network, capture repair, or external parser.
#![forbid(unsafe_code)]
use pcap_evidence::{json::Json, sha256};
use pcap_evidence_product::protocols::Protocol;
use std::{
    fs::File,
    io::{self, Read, Write},
};

fn run(args: &[String]) -> Result<(), String> {
    if args == ["--version"] {
        println!("pcap-evidence-research-probe {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }
    if args.len() != 2 {
        return Err("usage: research_probe PROTOCOL PAYLOAD_FILE".into());
    }
    let protocol = Protocol::ALL
        .iter()
        .copied()
        .find(|p| p.name() == args[0])
        .ok_or_else(|| "unknown research protocol".to_string())?;
    let mut bytes = Vec::new();
    File::open(&args[1])
        .map_err(|_| "cannot open selected payload")?
        .take(65537)
        .read_to_end(&mut bytes)
        .map_err(|_| "payload read failed")?;
    if bytes.len() > 65536 {
        return Err("research payload exceeds 65536 bytes".into());
    }
    let result = match protocol.decode(&bytes) {
        Ok(decoded) => Json::object([
            ("result", "decoded".into()),
            ("consumed", decoded.consumed.to_string().into()),
            ("decoded", decoded.json()),
        ]),
        Err(error) => Json::object([
            ("result", "error".into()),
            ("code", error.code.as_str().into()),
            ("detail", error.to_string().into()),
        ]),
    };
    let output = Json::object([
        ("schema", "pcap-evidence.research-probe.v1".into()),
        ("producer", "independent-native-decoder".into()),
        ("protocol", protocol.name().into()),
        ("compiled", protocol.compiled().into()),
        (
            "payload_sha256",
            sha256::hex(&sha256::digest(&bytes)).into(),
        ),
        ("observation", result),
    ])
    .encode_bounded_line(2 * 1024 * 1024)
    .map_err(|e| e.to_string())?;
    io::stdout()
        .lock()
        .write_all(output.as_bytes())
        .map_err(|_| "output write failed")?;
    Ok(())
}
fn main() {
    let args = std::env::args_os()
        .skip(1)
        .map(|x| x.into_string())
        .collect::<Result<Vec<_>, _>>();
    let result = args
        .map_err(|_| "arguments must be UTF-8".to_string())
        .and_then(|args| run(&args));
    if let Err(error) = result {
        eprintln!("{error}");
        std::process::exit(2);
    }
}
