//! Raw capture clocks are never automatically synchronized or converted with floats.
use crate::{Error, ErrorCode, Result};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Resolution {
    Decimal(u8),
    Binary(u8),
}
impl Resolution {
    pub fn from_pcapng(value: u8) -> Self {
        if value & 0x80 == 0 {
            Self::Decimal(value)
        } else {
            Self::Binary(value & 0x7f)
        }
    }
    pub fn to_pcapng(self) -> Result<u8> {
        match self {
            Self::Decimal(x) if x <= 127 => Ok(x),
            Self::Binary(x) if x <= 127 => Ok(x | 0x80),
            _ => Err(Error::new(
                ErrorCode::InvalidTimestamp,
                0,
                "resolution",
                "exponent exceeds 127",
            )),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Timestamp {
    pub ticks: u64,
    pub resolution: Resolution,
    pub offset_seconds: i64,
}
impl Timestamp {
    pub fn legacy(seconds: u32, fraction: u32, nanos: bool) -> Result<Self> {
        let scale = if nanos {
            1_000_000_000u64
        } else {
            1_000_000u64
        };
        if u64::from(fraction) >= scale {
            return Err(Error::new(
                ErrorCode::InvalidTimestamp,
                0,
                "timestamp_fraction",
                "fraction exceeds one second",
            ));
        }
        Ok(Self {
            ticks: u64::from(seconds) * scale + u64::from(fraction),
            resolution: Resolution::Decimal(if nanos { 9 } else { 6 }),
            offset_seconds: 0,
        })
    }

    /// Exact conversion only. Fine-resolution nonintegral nanoseconds remain typed unavailable.
    pub fn unix_nanos(self) -> Result<i128> {
        self.resolution.to_pcapng()?;
        let bad = || {
            Error::new(
                ErrorCode::InexactTimestamp,
                0,
                "timestamp",
                "not exactly representable as signed nanoseconds",
            )
        };
        let part: u128 = match self.resolution {
            Resolution::Decimal(e) if e <= 9 => {
                u128::from(self.ticks) * 10u128.pow(u32::from(9 - e))
            }
            Resolution::Decimal(e) => {
                if self.ticks == 0 {
                    0
                } else {
                    let divisor = 10u128.checked_pow(u32::from(e - 9)).ok_or_else(bad)?;
                    if u128::from(self.ticks) % divisor != 0 {
                        return Err(bad());
                    }
                    u128::from(self.ticks) / divisor
                }
            }
            Resolution::Binary(e) => {
                let numerator = u128::from(self.ticks) * 1_000_000_000;
                let divisor = 1u128.checked_shl(u32::from(e)).ok_or_else(bad)?;
                if numerator % divisor != 0 {
                    return Err(bad());
                }
                numerator / divisor
            }
        };
        let part = i128::try_from(part).map_err(|_| bad())?;
        part.checked_add(i128::from(self.offset_seconds) * 1_000_000_000)
            .ok_or_else(bad)
    }

    pub fn legacy_parts(self, nanos: bool) -> Result<(u32, u32)> {
        let value = self.unix_nanos()?;
        if value < 0 {
            return Err(Error::new(
                ErrorCode::InvalidTimestamp,
                0,
                "timestamp",
                "classic PCAP cannot represent negative seconds",
            ));
        }
        let seconds = u32::try_from(value / 1_000_000_000).map_err(|_| {
            Error::new(
                ErrorCode::InvalidTimestamp,
                0,
                "timestamp",
                "seconds exceed classic PCAP u32",
            )
        })?;
        let fraction = (value % 1_000_000_000) as u32;
        if !nanos && fraction % 1000 != 0 {
            return Err(Error::new(
                ErrorCode::InexactTimestamp,
                0,
                "timestamp",
                "would discard sub-microsecond precision",
            ));
        }
        Ok((seconds, if nanos { fraction } else { fraction / 1000 }))
    }
}
