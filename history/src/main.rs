#![forbid(unsafe_code)]
use pcap_evidence::{json::Json, sha256};
use pcap_evidence_history::query::History;
use pcap_evidence_history::{
    analyze_file, recover_file, verify_file, Cancellation, Config, EpochPolicy,
};
use std::{collections::BTreeSet, path::Path};
const HELP:&str="pcap-history build SOURCE NEW_WORKSPACE [OPTIONS]\npcap-history verify SOURCE WORKSPACE NEW_REPLAY_WORKSPACE\npcap-history recover SOURCE OLD_WORKSPACE NEW_WORKSPACE [--allow-torn-tail]\npcap-history generations SOURCE WORKSPACE [--after GENERATION_HEX]\npcap-history range SOURCE WORKSPACE GENERATION_HEX DIRECTION START END\n\nBuild options: --nearest-frontier (explicit epoch hypothesis; default strict)\n--max-disk-bytes N --max-source-bytes N --hot-tuples N --sort-entries N\n--checkpoint-records N --max-generations N\nAll query bytes are capture-derived hypotheses, never endpoint truth.\nGeneration pages include payload-bearing hypotheses only. No live acquisition.\nAn interrupted build is unsealed; use explicit recovery to a NEW workspace.";
fn generation(s: &str) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    if s.len() != 64 || !s.is_ascii() {
        return Err("generation must be 64 hexadecimal characters".into());
    }
    let mut id = [0; 32];
    for (n, b) in id.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[n * 2..n * 2 + 2], 16)?;
    }
    Ok(id)
}
fn build_config(options: &[String]) -> Result<Config, Box<dyn std::error::Error>> {
    let mut c = Config::default();
    let mut i = 0;
    let mut seen = BTreeSet::new();
    while i < options.len() {
        let flag = options[i].as_str();
        if !seen.insert(flag) {
            return Err("duplicate history option".into());
        }
        i += 1;
        if flag == "--nearest-frontier" {
            c.epoch_policy = EpochPolicy::NearestFrontier;
            continue;
        }
        let value = options.get(i).ok_or("history option needs a value")?;
        i += 1;
        match flag {
            "--max-disk-bytes" => c.max_disk_bytes = value.parse()?,
            "--max-source-bytes" => c.max_source_bytes = value.parse()?,
            "--hot-tuples" => c.hot_tuples = value.parse()?,
            "--sort-entries" => c.sort_entries = value.parse()?,
            "--checkpoint-records" => c.checkpoint_records = value.parse()?,
            "--max-generations" => c.max_generations = value.parse()?,
            _ => return Err("unknown history option".into()),
        }
    }
    c.validate()?;
    Ok(c)
}
fn run() -> Result<(), Box<dyn std::error::Error>> {
    let a: Vec<String> = std::env::args().skip(1).collect();
    if a.is_empty() || (a.len() == 1 && a[0] == "--help") {
        println!("{HELP}");
        return Ok(());
    }
    let cancel = Cancellation::default();
    let value = match a[0].as_str() {
        "build" if a.len() >= 3 => analyze_file(
            Path::new(&a[1]),
            Path::new(&a[2]),
            build_config(&a[3..])?,
            &cancel,
        )?
        .json(),
        "verify" if a.len() == 4 => {
            let s = verify_file(
                Path::new(&a[1]),
                Path::new(&a[2]),
                Path::new(&a[3]),
                &cancel,
            )?;
            Json::object([
                ("semantic_replay_verified", true.into()),
                ("summary", s.json()),
            ])
        }
        "recover" if a.len() == 4 || (a.len() == 5 && a[4] == "--allow-torn-tail") => recover_file(
            Path::new(&a[1]),
            Path::new(&a[2]),
            Path::new(&a[3]),
            a.len() == 5,
            &cancel,
        )?
        .json(),
        "generations" if a.len() == 3 || (a.len() == 5 && a[3] == "--after") => {
            let mut h = History::open(Path::new(&a[1]), Path::new(&a[2]))?;
            let after = if a.len() == 5 {
                Some(generation(&a[4])?)
            } else {
                None
            };
            let ids = h.generations(after, 200)?;
            let last = ids.last().copied();
            let more = if last.is_some() {
                !h.generations(last, 1)?.is_empty()
            } else {
                false
            };
            Json::object([
                ("schema", "pcap-evidence.history-generations.v1".into()),
                (
                    "generations",
                    Json::array(ids.iter().map(|g| sha256::hex(g).into())),
                ),
                ("next", last.map_or(Json::Null, |g| sha256::hex(&g).into())),
                ("has_more", more.into()),
                ("scope", "payload_bearing_generation_hypotheses".into()),
            ])
        }
        "range" if a.len() == 7 => {
            let id = generation(&a[3])?;
            let mut h = History::open(Path::new(&a[1]), Path::new(&a[2]))?;
            h.range(id, a[4].parse()?, a[5].parse()?, a[6].parse()?)?
        }
        _ => return Err("invalid command; use --help".into()),
    };
    println!("{}", value.encode_bounded(16 * 1024 * 1024)?);
    Ok(())
}
fn main() {
    if let Err(e) = run() {
        eprintln!(
            "{}",
            Json::object([("error", e.to_string().into()), ("complete", false.into())]).encode()
        );
        std::process::exit(2);
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn options(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| (*x).to_owned()).collect()
    }
    #[test]
    fn configured_budgets_are_not_hidden_defaults() {
        let c = build_config(&options(&[
            "--max-disk-bytes",
            "1048576",
            "--hot-tuples",
            "2",
        ]))
        .unwrap();
        assert_eq!(c.max_disk_bytes, 1048576);
        assert_eq!(c.hot_tuples, 2);
    }
    #[test]
    fn malformed_cli_options_are_rejected() {
        for v in [
            vec!["--sort-entries", "0"],
            vec!["--hot-tuples"],
            vec!["--nearest-frontier", "--nearest-frontier"],
            vec!["--unknown", "1"],
        ] {
            assert!(build_config(&options(&v)).is_err());
        }
    }
}
