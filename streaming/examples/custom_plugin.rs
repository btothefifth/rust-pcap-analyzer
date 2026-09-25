//! A complete, trusted UDP plugin registered without changing runner.rs.
//! Example protocol only: ECHOX01 followed by arbitrary bytes. No network I/O.
#![forbid(unsafe_code)]
use pcap_evidence::{
    json::Json,
    protocol::{ProbeInput, ProbeResult, ProbeStrength, ProbeTransport},
};
use pcap_evidence_stream::plugin::{
    AnalyzerLimits, AnalyzerPlugin, DatagramAnalyzer, DatagramInput, Output, ProtocolDetector,
    StreamAnalyzer,
};
use pcap_evidence_stream::{analyze_reader, NdjsonSink, Registry, Result, StreamConfig};
use std::{
    fs::File,
    io::{self, BufReader, BufWriter},
};

const SIGNATURE: &[u8] = b"ECHOX01";
struct EchoPlugin;
impl ProtocolDetector for EchoPlugin {
    fn protocol(&self) -> &'static str {
        "example.echo"
    }
    fn detect(&self, input: &ProbeInput<'_>) -> ProbeResult {
        if input.transport != ProbeTransport::Udp {
            return ProbeResult::NoMatch;
        }
        let compared = input.prefix.len().min(SIGNATURE.len());
        if input.prefix[..compared] != SIGNATURE[..compared] {
            return ProbeResult::NoMatch;
        }
        if input.prefix.len() < SIGNATURE.len() {
            return ProbeResult::NeedMore {
                minimum_total: SIGNATURE.len(),
            };
        }
        ProbeResult::Match {
            protocol: self.protocol(),
            strength: ProbeStrength::HeaderStructure,
            examined_bytes: SIGNATURE.len(),
            reason: "example protocol marker only; not authentication",
        }
    }
}
impl AnalyzerPlugin for EchoPlugin {
    fn stream(&self, _: AnalyzerLimits) -> Option<Box<dyn StreamAnalyzer>> {
        None
    }
    fn datagram(&self, limits: AnalyzerLimits) -> Option<Box<dyn DatagramAnalyzer>> {
        Some(Box::new(EchoDatagram {
            max_bytes: limits.max_buffer_bytes,
        }))
    }
}
struct EchoDatagram {
    max_bytes: usize,
}
impl DatagramAnalyzer for EchoDatagram {
    fn retained_bytes(&self) -> usize {
        0
    }
    fn analyze(&mut self, input: &DatagramInput<'_>, out: &mut Output<'_>) -> Result<()> {
        if input.bytes.len() > self.max_bytes {
            return Err(pcap_evidence_stream::Error::limit("example_echo_bytes"));
        }
        if !input.bytes.data().starts_with(SIGNATURE) {
            return out.issue("example.echo", "marker_not_present", input.bytes);
        }
        out.message(
            "example.echo",
            input.bytes,
            None,
            Json::object([
                ("marker_version", "ECHOX01".into()),
                (
                    "payload_bytes",
                    (input.bytes.len() - SIGNATURE.len()).to_string().into(),
                ),
            ]),
            None,
            true,
        )?;
        Ok(())
    }
}
fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args_os().skip(1);
    let capture = args.next().ok_or("usage: custom_plugin CAPTURE")?;
    if args.next().is_some() {
        return Err("usage: custom_plugin CAPTURE".into());
    }
    let config = StreamConfig::default();
    let mut registry = Registry::builtins(&config)?;
    registry.register(Box::new(EchoPlugin))?;
    let mut sink = NdjsonSink::new(
        BufWriter::new(io::stdout().lock()),
        "example-plugin-run",
        config.max_event_bytes,
    )?;
    analyze_reader(
        BufReader::new(File::open(capture)?),
        config,
        &registry,
        &mut sink,
    )?;
    sink.finish()?;
    Ok(())
}
