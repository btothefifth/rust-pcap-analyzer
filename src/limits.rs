use crate::{Error, ErrorCode, Result};

/// Budgets are rejection thresholds, not silent truncation settings.
#[derive(Clone, Debug)]
pub struct Limits {
    pub max_input_bytes: usize,
    pub max_block_bytes: usize,
    pub max_packet_bytes: usize,
    pub max_records: usize,
    pub max_interfaces: usize,
    pub max_options: usize,
    pub max_flows: usize,
    pub max_segments_per_flow: usize,
    pub max_stream_span: usize,
    pub max_retained_payload: usize,
    pub max_fragment_sets: usize,
    pub max_fragments_per_set: usize,
    pub fragment_frame_lifetime: u64,
    pub max_protocol_messages: usize,
    pub max_application_bytes: usize,
    pub max_labels: usize,
    pub max_correlation_checks: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            max_input_bytes: 256 * 1024 * 1024,
            max_block_bytes: 16 * 1024 * 1024,
            max_packet_bytes: 1024 * 1024,
            max_records: 1_000_000,
            max_interfaces: 1024,
            max_options: 4096,
            max_flows: 4096,
            max_segments_per_flow: 16_384,
            max_stream_span: 4 * 1024 * 1024,
            max_retained_payload: 64 * 1024 * 1024,
            max_fragment_sets: 1024,
            max_fragments_per_set: 1024,
            fragment_frame_lifetime: 100_000,
            max_protocol_messages: 100_000,
            max_application_bytes: 1024 * 1024,
            max_labels: 10_000,
            max_correlation_checks: 5_000_000,
        }
    }
}
impl Limits {
    pub fn validate(&self) -> Result<()> {
        let nonzero = [
            self.max_input_bytes,
            self.max_block_bytes,
            self.max_packet_bytes,
            self.max_records,
            self.max_interfaces,
            self.max_options,
            self.max_flows,
            self.max_segments_per_flow,
            self.max_stream_span,
            self.max_retained_payload,
            self.max_fragment_sets,
            self.max_fragments_per_set,
            self.max_protocol_messages,
            self.max_application_bytes,
            self.max_labels,
            self.max_correlation_checks,
        ];
        if nonzero.contains(&0) || self.fragment_frame_lifetime == 0 {
            return Err(Error::new(
                ErrorCode::Usage,
                0,
                "limits",
                "all resource limits must be positive",
            ));
        }
        if self.max_stream_span >= (1usize << 30) || self.max_block_bytes < 28 {
            return Err(Error::new(
                ErrorCode::Usage,
                0,
                "limits",
                "stream span must be < 2^30 and block limit >= 28",
            ));
        }
        Ok(())
    }
}
