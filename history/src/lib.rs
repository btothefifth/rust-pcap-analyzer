//! Disk-retained TCP observations and explicit reconstruction policies.
//! No endpoint truth, automatic attack verdict, or unbounded protocol history is
//! inferred. See docs/history/CONTRACT.md for the exact supported subset.
#![forbid(unsafe_code)]
pub mod codec;
pub mod index;
pub mod journal;
pub mod model;
pub mod pipeline;
pub mod query;
pub mod state;

pub use model::{Config, EpochPolicy, Key, SourceIdentity, TcpInput, Witness};
pub use pcap_evidence::{Error, ErrorCode, Result};
pub use pipeline::{analyze_file, recover_file, verify_file, Cancellation, Summary};

pub(crate) fn bad(field: &'static str, detail: impl Into<String>) -> Error {
    Error::new(ErrorCode::Invariant, 0, field, detail)
}
