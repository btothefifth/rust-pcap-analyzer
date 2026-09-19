//! Auditable offline network reconstruction. No unsafe Rust or runtime dependencies.
//!
//! Start with [`capture::CaptureIter`] for borrowed, zero-copy container records,
//! [`capture::CaptureReader`] for bounded streaming, or [`engine::analyze`] for an
//! end-to-end report. An analysis is evidence, not an intrusion verdict.
#![forbid(unsafe_code)]

pub mod capture;
pub mod checksum;
pub mod correlate;
pub mod datagram;
pub mod dnp3;
pub mod engine;
pub mod error;
pub mod fragment;
pub mod index;
pub mod json;
pub mod limits;
pub mod modbus;
pub mod protocol;
pub mod provenance;
pub mod publish;
pub mod report;
pub mod semantics;
pub mod sha256;
pub mod tcp;
pub mod time;
pub mod wire;
pub mod writer;

pub use error::{Error, ErrorCode, Result};
pub use limits::Limits;

// Streaming handoff: content dispatch and shared CLI parsing.
pub mod cli_ports;
pub mod detection;
