//! Small native, source-backed test adapter. Arguments never invoke other tools.
use pcap_evidence::{
    json::Json,
    modbus::Role,
    provenance::{EvidenceBytes, PacketId},
    semantics::{self, dnp3, modbus, Limits},
};
use std::io::{Read, Write};
fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.len() != 3 {
        return Err("usage: semantic_probe dnp3|modbus read|request|response|unknown FILE".into());
    }
    let mut data = Vec::new();
    std::fs::File::open(&args[2])?
        .take(65_537)
        .read_to_end(&mut data)?;
    if data.len() > 65_536 {
        return Err("input limit".into());
    }
    let b = EvidenceBytes::from_packet(
        &data,
        PacketId {
            capture: pcap_evidence::sha256::digest(&data),
            frame: 1,
            record_offset: 0,
        },
        0,
    );
    let report = match args[0].as_str() {
        "dnp3" => semantics::as_json(dnp3::decode(
            &b,
            match args[1].as_str() {
                "read" => dnp3::Context::ReadHeaders,
                "response" => dnp3::Context::ResponseValues,
                _ => dnp3::Context::UnsupportedFunction,
            },
            Limits::default(),
        )),
        "modbus" => {
            let role = match args[1].as_str() {
                "request" => Role::Request,
                "response" => Role::Response,
                "unknown" => Role::Unknown,
                _ => return Err("unknown role".into()),
            };
            if role == Role::Unknown {
                modbus::alternatives_json(&b, role, Limits::default())
            } else {
                semantics::as_json(modbus::decode(&b, role, Limits::default()))
            }
        }
        _ => return Err("unknown protocol".into()),
    };
    let value = Json::object([
        ("producer", "pcap-evidence/semantic-probe-v1".into()),
        ("report", report),
    ]);
    std::io::stdout()
        .lock()
        .write_all(value.encode_bounded_line(4 * 1024 * 1024)?.as_bytes())?;
    Ok(())
}
fn main() {
    if let Err(e) = run() {
        eprintln!("semantic probe failed: {e}");
        std::process::exit(2);
    }
}
