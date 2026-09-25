//! Incremental capture input, bounded reconstruction windows, and versioned evidence events.
//!
//! A window/session ID identifies an analysis scope, NOT an asserted endpoint TCP
//! connection. Every budget/idle cut is emitted. No protocol state crosses a cut.
//! This avoids claiming that discarded retransmission history can still be verified.
//! The companion analytics tool stores events and secondary indexes out of core.
#![forbid(unsafe_code)]
pub mod config;
pub mod events;
pub mod network;
pub mod plugin;
pub mod protocols;
pub mod runner;

pub use config::StreamConfig;
pub use events::{Event, EventKind, EventSink, EvidenceStatus, NdjsonSink};
pub use pcap_evidence::{Error, ErrorCode, Result};
pub use plugin::{
    DatagramAnalyzer, ProtocolDetector, Registry, StreamAnalyzer, TransactionCorrelator,
};
pub use runner::{analyze_reader, Summary};

pub(crate) fn malformed(field: &'static str, detail: impl Into<String>) -> Error {
    Error::new(ErrorCode::ProtocolFraming, 0, field, detail)
}
