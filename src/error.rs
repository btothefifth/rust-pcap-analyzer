use std::fmt;

pub type Result<T> = std::result::Result<T, Error>;

/// Stable machine-readable failure families; never an attack classification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ErrorCode {
    Io,
    Usage,
    BadMagic,
    UnsupportedVersion,
    Truncated,
    InvalidLength,
    LengthMismatch,
    InvalidOption,
    MissingInterface,
    InvalidTimestamp,
    InexactTimestamp,
    LimitExceeded,
    UnsupportedLink,
    UnsupportedNetwork,
    UnsupportedTransport,
    MalformedPacket,
    Checksum,
    FragmentConflict,
    SequenceAmbiguous,
    ProtocolFraming,
    InvalidIndex,
    SourceMismatch,
    InvalidLabel,
    OutputExists,
    Invariant,
}

impl ErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Io => "io",
            Self::Usage => "usage",
            Self::BadMagic => "bad_magic",
            Self::UnsupportedVersion => "unsupported_version",
            Self::Truncated => "truncated",
            Self::InvalidLength => "invalid_length",
            Self::LengthMismatch => "length_mismatch",
            Self::InvalidOption => "invalid_option",
            Self::MissingInterface => "missing_interface",
            Self::InvalidTimestamp => "invalid_timestamp",
            Self::InexactTimestamp => "inexact_timestamp",
            Self::LimitExceeded => "limit_exceeded",
            Self::UnsupportedLink => "unsupported_link",
            Self::UnsupportedNetwork => "unsupported_network",
            Self::UnsupportedTransport => "unsupported_transport",
            Self::MalformedPacket => "malformed_packet",
            Self::Checksum => "checksum",
            Self::FragmentConflict => "fragment_conflict",
            Self::SequenceAmbiguous => "sequence_ambiguous",
            Self::ProtocolFraming => "protocol_framing",
            Self::InvalidIndex => "invalid_index",
            Self::SourceMismatch => "source_mismatch",
            Self::InvalidLabel => "invalid_label",
            Self::OutputExists => "output_exists",
            Self::Invariant => "invariant",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Error {
    pub code: ErrorCode,
    pub offset: u64,
    pub field: &'static str,
    pub detail: String,
}

impl Error {
    pub fn new(
        code: ErrorCode,
        offset: u64,
        field: &'static str,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            code,
            offset,
            field,
            detail: detail.into(),
        }
    }
    pub fn io(error: std::io::Error) -> Self {
        Self::new(ErrorCode::Io, 0, "io", error.to_string())
    }
    pub fn limit(field: &'static str) -> Self {
        Self::new(
            ErrorCode::LimitExceeded,
            0,
            field,
            "configured resource budget exceeded",
        )
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} at byte {} ({}): {}",
            self.code.as_str(),
            self.offset,
            self.field,
            self.detail
        )
    }
}
impl std::error::Error for Error {}
impl From<std::io::Error> for Error {
    fn from(value: std::io::Error) -> Self {
        Self::io(value)
    }
}

pub(crate) fn require(data: &[u8], count: usize, offset: u64, field: &'static str) -> Result<()> {
    if data.len() < count {
        Err(Error::new(
            ErrorCode::Truncated,
            offset,
            field,
            format!("need {count} bytes; have {}", data.len()),
        ))
    } else {
        Ok(())
    }
}
