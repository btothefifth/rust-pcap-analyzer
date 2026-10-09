use std::{
    fs,
    path::PathBuf,
    process::{Command, Output},
    sync::atomic::{AtomicU64, Ordering},
};

static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

struct TestRoot(PathBuf);

impl TestRoot {
    fn new() -> Self {
        loop {
            let path = std::env::temp_dir().join(format!(
                "pcap-history-app-generation-{}-{}",
                std::process::id(),
                NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Self(path),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("create test root {}: {error}", path.display()),
            }
        }
    }
}

impl Drop for TestRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn invoke(generation: &str) -> Output {
    let root = TestRoot::new();
    let history = root.0.join("history");
    fs::create_dir(&history).expect("create empty history workspace");
    Command::new(env!("CARGO_BIN_EXE_pcap-evidence-history-app"))
        .arg(root.0.join("missing.pcap"))
        .arg(history)
        .arg(generation)
        .arg("0")
        .arg("dns")
        .arg(root.0.join("out.ndjson"))
        .output()
        .expect("run history-app CLI")
}

fn assert_rejected_generation(output: Output) {
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(4), "stderr: {stderr}");
    assert_eq!(
        stderr.trim(),
        "history application analysis: generation must be 64 hexadecimal characters"
    );
}

fn assert_valid_generation_reaches_history_open(output: Output) {
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(4), "stderr: {stderr}");
    assert!(
        stderr.contains("history application analysis: io at byte 0 (io):"),
        "stderr: {stderr}"
    );
    assert!(!stderr.contains("generation must be 64 hexadecimal characters"));
    assert!(!stderr.contains("panicked at"), "stderr: {stderr}");
}

#[test]
fn generation_rejects_non_ascii_64_byte_input_without_unwinding() {
    let generation = format!("aé{}", "a".repeat(61));
    assert_eq!(generation.len(), 64);
    assert_eq!(generation.chars().count(), 63);
    assert_rejected_generation(invoke(&generation));
}

#[test]
fn generation_rejects_wrong_length_without_unwinding() {
    assert_rejected_generation(invoke(&"a".repeat(63)));
}

#[test]
fn generation_rejects_non_hex_ascii_without_unwinding() {
    assert_rejected_generation(invoke(&"g".repeat(64)));
}

#[test]
fn generation_rejects_ascii_signs_without_unwinding() {
    assert_rejected_generation(invoke(&"+a".repeat(32)));
}

#[test]
fn generation_accepts_lowercase_hex_and_reaches_history_open() {
    assert_valid_generation_reaches_history_open(invoke(&"a".repeat(64)));
}

#[test]
fn generation_accepts_uppercase_hex_and_reaches_history_open() {
    assert_valid_generation_reaches_history_open(invoke(&"A".repeat(64)));
}
