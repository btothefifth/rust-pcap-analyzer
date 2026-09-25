//! Additive product layer. The existing independent engine remains authoritative
//! for its own interpretation. Comparison tools never vote on canonical results.
#![forbid(unsafe_code)]
pub mod deep;
pub mod layer;
pub mod output;
pub mod protocols;
pub mod registry;
#[cfg(feature = "binary")]
pub mod tlv;
pub use pcap_evidence::{Error, ErrorCode, Result};
