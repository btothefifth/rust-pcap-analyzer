//! OS arguments reach the depth CLI's controlled error boundary.
use std::process::Command;

#[test]
fn depth_help_remains_successful() {
    let output = Command::new(env!("CARGO_BIN_EXE_pcap-depth"))
        .arg("--help")
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(String::from_utf8(output.stdout)
        .unwrap()
        .contains("pcap-depth"));
}

#[cfg(unix)]
#[test]
fn non_utf8_argument_is_a_typed_usage_error() {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;
    let output = Command::new(env!("CARGO_BIN_EXE_pcap-depth"))
        .args(["decode", "stp"])
        .arg(OsString::from_vec(vec![0xff]))
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    let error = String::from_utf8(output.stderr).unwrap();
    assert!(error.contains("\"field\":\"arguments\""));
    assert!(error.contains("UTF-8"));
    assert!(!error.contains("panicked"));
}
