#![forbid(unsafe_code)]
use pcap_evidence_history::query::History;
use pcap_evidence_history_app::{analyze, Request};
use pcap_evidence_product::deep::Limits;
use std::{io::Write, path::Path};
fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() < 6 {
        return Err("USAGE: pcap-evidence-history-app CAPTURE HISTORY_DIR GENERATION_HEX DIRECTION PROTOCOL NEW_OUTPUT [--ua-security-none]".into());
    }
    if args[2].len() != 64 {
        return Err("generation must be 64 hex digits".into());
    }
    let mut generation = [0u8; 32];
    for (i, x) in generation.iter_mut().enumerate() {
        *x = u8::from_str_radix(&args[2][2 * i..2 * i + 2], 16)?;
    }
    if args.len() > 7 || args.get(6).is_some_and(|x| x != "--ua-security-none") {
        return Err("unknown option".into());
    }
    let direction = args[3].parse::<u8>()?;
    let mut history = History::open(Path::new(&args[0]), Path::new(&args[1]))?;
    let (start, end) = history
        .extent(generation, direction, 1_000_000_000)?
        .ok_or("generation/direction has no intervals")?;
    let request = Request {
        generation,
        direction,
        start,
        end,
        page_bytes: history.config.max_query_bytes.min(65536),
        max_output_bytes: 8 * 1024 * 1024 * 1024,
        protocol: args[4].clone(),
        ua_security_none: args.len() == 7,
    };
    let out = Path::new(&args[5]);
    let partial = out.with_extension("history-app.partial");
    if out.exists() {
        return Err("output exists".into());
    }
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&partial)?;
    let mut writer = std::io::BufWriter::new(file);
    let cancel = std::sync::atomic::AtomicBool::new(false);
    analyze(
        &mut history,
        &request,
        Limits::default(),
        &mut writer,
        &cancel,
    )?;
    writer.flush()?;
    writer.get_ref().sync_all()?;
    std::fs::hard_link(&partial, out)?;
    std::fs::remove_file(partial)?;
    Ok(())
}
fn main() {
    if let Err(e) = run() {
        eprintln!("history application analysis: {e}");
        std::process::exit(4);
    }
}
