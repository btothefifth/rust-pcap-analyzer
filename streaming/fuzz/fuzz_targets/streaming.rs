#![no_main]
use libfuzzer_sys::fuzz_target;
use pcap_evidence_stream::{analyze_reader, Event, EventSink, Registry, Result, StreamConfig};
struct Sink(u64);
impl EventSink for Sink {
    fn run_id(&self) -> &str {
        "fuzz"
    }
    fn emit(&mut self, _: &Event) -> Result<u64> {
        self.0 += 1;
        Ok(self.0)
    }
}
fuzz_target!(|data: &[u8]| {
    if data.len() > 65536 {
        return;
    }
    let mut c = StreamConfig::default();
    c.max_active_keys = 4;
    c.max_active_payload = 65536;
    c.window_payload = 16384;
    c.window_packets = 128;
    c.max_plugin_events = 256;
    c.max_plugin_bytes = 65536;
    let registry = Registry::builtins(&c).expect("constant registry configuration");
    let _ = analyze_reader(data, c, &registry, &mut Sink(0));
});
