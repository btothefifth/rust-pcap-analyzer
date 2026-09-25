use crate::{malformed, Result};
use pcap_evidence::{capture::ParseMode, engine::Config, json::Json, Limits};

/// Finite budgets on retained state, independent of total capture size.
/// Counts/bytes are logical limits, not an allocator/RSS reservation or sandbox.
#[derive(Clone, Debug)]
pub struct StreamConfig {
    pub base: Config,
    pub max_active_keys: usize,
    pub max_active_payload: usize,
    pub window_payload: usize,
    pub window_packets: usize,
    pub idle_frames: u64,
    pub max_tunnel_contexts: usize,
    pub max_tunnel_depth: usize,
    pub fragment_payload: usize,
    pub max_event_bytes: usize,
    pub max_plugin_bytes: usize,
    pub max_plugin_events: usize,
    pub max_detectors: usize,
    pub max_probe_bytes: usize,
    pub max_source_bytes: u64,
    pub include_payload: bool,
    pub allow_port_hints: bool,
}
impl Default for StreamConfig {
    fn default() -> Self {
        Self {
            base: Config::default(),
            max_active_keys: 256,
            max_active_payload: 32 * 1024 * 1024,
            window_payload: 256 * 1024,
            window_packets: 2048,
            idle_frames: 100_000,
            max_tunnel_contexts: 32,
            max_tunnel_depth: 4,
            fragment_payload: 8 * 1024 * 1024,
            max_event_bytes: 8 * 1024 * 1024,
            max_plugin_bytes: 1024 * 1024,
            max_plugin_events: 4096,
            max_detectors: 16,
            max_probe_bytes: 4096,
            // SHA-256's standard bit-length field is u64. Do not wrap it.
            max_source_bytes: u64::MAX / 8,
            include_payload: false,
            allow_port_hints: false,
        }
    }
}
impl StreamConfig {
    pub fn validate(&self) -> Result<()> {
        self.base.validate()?;
        if usize::BITS < 64 {
            return Err(malformed(
                "platform",
                "large-capture mode requires a 64-bit target",
            ));
        }
        if [
            self.max_active_keys,
            self.max_active_payload,
            self.window_payload,
            self.window_packets,
            self.max_tunnel_contexts,
            self.max_tunnel_depth,
            self.fragment_payload,
            self.max_event_bytes,
            self.max_plugin_bytes,
            self.max_plugin_events,
            self.max_detectors,
            self.max_probe_bytes,
        ]
        .contains(&0)
            || self.idle_frames == 0
            || self.max_source_bytes == 0
        {
            return Err(malformed(
                "stream_limits",
                "all streaming limits must be positive",
            ));
        }
        if self.window_payload > self.max_active_payload
            || self.window_payload > self.base.limits.max_stream_span
            || self.window_packets > self.base.limits.max_segments_per_flow
            || self.max_source_bytes > u64::MAX / 8
            || self.max_tunnel_contexts > 256
            || self.max_tunnel_depth > 16
            || self.max_active_keys > 65_536
            || self.max_detectors > 64
            || self.max_probe_bytes > self.max_plugin_bytes
            || self.fragment_payload / self.max_tunnel_contexts < 65_535
        {
            return Err(malformed(
                "stream_limits",
                "inconsistent or excessive streaming budgets",
            ));
        }
        Ok(())
    }
    pub fn reader_limits(&self) -> Limits {
        let mut l = self.base.limits.clone();
        l.max_input_bytes = self.max_source_bytes as usize;
        l.max_records = usize::MAX;
        l
    }
    pub fn tracker_limits(&self) -> Limits {
        let mut l = self.base.limits.clone();
        l.max_retained_payload = self.window_payload;
        l.max_segments_per_flow = self.window_packets;
        l.max_flows = self.window_packets.min(256);
        l
    }
    pub fn fragment_limits(&self) -> Limits {
        let mut l = self.base.limits.clone();
        l.max_retained_payload = self.fragment_payload / self.max_tunnel_contexts;
        l.max_fragment_sets =
            (self.base.limits.max_fragment_sets / self.max_tunnel_contexts).max(1);
        l
    }
    /// Exact policy snapshot for deterministic replay, not a confidence claim.
    pub fn json(&self) -> Json {
        Json::object([
            ("max_active_keys", self.max_active_keys.into()),
            ("max_active_payload", self.max_active_payload.into()),
            ("window_payload", self.window_payload.into()),
            ("window_packets", self.window_packets.into()),
            ("idle_frames", self.idle_frames.to_string().into()),
            ("max_tunnel_contexts", self.max_tunnel_contexts.into()),
            ("max_tunnel_depth", self.max_tunnel_depth.into()),
            ("fragment_payload", self.fragment_payload.into()),
            ("max_event_bytes", self.max_event_bytes.into()),
            ("max_plugin_bytes", self.max_plugin_bytes.into()),
            ("max_plugin_events", self.max_plugin_events.into()),
            ("max_detectors", self.max_detectors.into()),
            ("max_probe_bytes", self.max_probe_bytes.into()),
            ("max_source_bytes", self.max_source_bytes.to_string().into()),
            ("include_payload", self.include_payload.into()),
            ("allow_port_hints", self.allow_port_hints.into()),
            (
                "parse_mode",
                match self.base.parse_mode {
                    ParseMode::Strict => "strict",
                    ParseMode::Evidence => "evidence",
                }
                .into(),
            ),
            ("overlap", self.base.overlap_policy.as_str().into()),
            (
                "checksums",
                format!("{:?}", self.base.checksum_policy).into(),
            ),
            (
                "idle_timeout_ns",
                self.base.idle_timeout_ns.to_string().into(),
            ),
            (
                "dnp3_ports",
                Json::array(self.base.dnp3_ports.iter().copied().map(Json::from)),
            ),
            (
                "modbus_ports",
                Json::array(self.base.modbus_ports.iter().copied().map(Json::from)),
            ),
            (
                "container_limits",
                Json::object([
                    ("max_block_bytes", self.base.limits.max_block_bytes.into()),
                    ("max_packet_bytes", self.base.limits.max_packet_bytes.into()),
                    ("max_interfaces", self.base.limits.max_interfaces.into()),
                    ("max_options", self.base.limits.max_options.into()),
                    ("max_stream_span", self.base.limits.max_stream_span.into()),
                    (
                        "max_fragment_sets",
                        self.base.limits.max_fragment_sets.into(),
                    ),
                    (
                        "max_fragments_per_set",
                        self.base.limits.max_fragments_per_set.into(),
                    ),
                    (
                        "fragment_frame_lifetime",
                        self.base.limits.fragment_frame_lifetime.to_string().into(),
                    ),
                    (
                        "max_protocol_messages",
                        self.base.limits.max_protocol_messages.into(),
                    ),
                    (
                        "max_application_bytes",
                        self.base.limits.max_application_bytes.into(),
                    ),
                    (
                        "max_correlation_checks",
                        self.base.limits.max_correlation_checks.into(),
                    ),
                ]),
            ),
        ])
    }
}
