//! Fixed-snapshot reads: admit a size, reserve it fallibly, and never read an
//! unbounded append stream. A one-byte probe detects growth without growing the
//! source buffer. These checks establish byte consistency, not authenticity.
use super::*;
use std::io::ErrorKind;

pub(super) fn read_snapshot(reader: &mut impl Read, size: usize) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(size)
        .map_err(|_| Error::limit("bgp_mrt_source_allocation"))?;
    bytes.resize(size, 0);
    reader.read_exact(&mut bytes).map_err(|error| {
        if error.kind() == ErrorKind::UnexpectedEof {
            Error::new(
                ErrorCode::LengthMismatch,
                0,
                "bgp_mrt_source",
                "source became shorter than its admitted size",
            )
        } else {
            error.into()
        }
    })?;
    let mut probe = [0u8; 1];
    loop {
        match reader.read(&mut probe) {
            Ok(0) => return Ok(bytes),
            Ok(_) => {
                return Err(Error::new(
                    ErrorCode::LengthMismatch,
                    0,
                    "bgp_mrt_source",
                    "source grew beyond its admitted size",
                ));
            }
            Err(error) if error.kind() == ErrorKind::Interrupted => continue,
            Err(error) => return Err(error.into()),
        }
    }
}

/// Read a regular MRT source file within one fixed metadata snapshot. No
/// network access, implicit decompression, or source mutation is performed.
pub fn read_source(path: &Path, maximum: u64) -> Result<Vec<u8>> {
    if maximum == 0 || maximum > 64 * 1024 * 1024 {
        return Err(Error::limit("bgp_mrt_input"));
    }
    let mut file = File::open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > maximum {
        return Err(Error::limit("bgp_mrt_input"));
    }
    let size = usize::try_from(metadata.len()).map_err(|_| Error::limit("bgp_mrt_input"))?;
    read_snapshot(&mut file, size)
}

/// Exact v1 size: magic/version, two length-prefixed labels, source length,
/// source hash, source bytes, and terminal hash. Checked before large buffers.
pub(super) fn encoded_size(input: usize, source: usize, checkpoint: usize) -> Result<usize> {
    FIXED_HEADER
        .checked_add(4)
        .and_then(|n| n.checked_add(source))
        .and_then(|n| n.checked_add(4))
        .and_then(|n| n.checked_add(checkpoint))
        .and_then(|n| n.checked_add(8))
        .and_then(|n| n.checked_add(DIGEST_BYTES))
        .and_then(|n| n.checked_add(input))
        .and_then(|n| n.checked_add(DIGEST_BYTES))
        .ok_or_else(|| Error::limit("bgp_mrt_store_bytes"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{self, Cursor};

    struct Growing {
        read_bytes: usize,
    }
    impl Read for Growing {
        fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
            out.fill(0x5a);
            self.read_bytes += out.len();
            Ok(out.len())
        }
    }

    #[test]
    fn serialized_size_matches_v1_layout_and_rejects_overflow() {
        assert_eq!(encoded_size(17, 3, 4).unwrap(), 90 + 17 + 3 + 4);
        assert!(encoded_size(usize::MAX, 1, 1).is_err());
        assert!(encoded_size(1, usize::MAX, 1).is_err());
        assert!(encoded_size(1, 1, usize::MAX).is_err());
    }

    #[test]
    fn growth_probe_never_reads_more_than_admitted_size_plus_one() {
        let mut reader = Growing { read_bytes: 0 };
        assert!(read_snapshot(&mut reader, 73).is_err());
        assert_eq!(reader.read_bytes, 74);
    }

    #[test]
    fn exact_source_is_preserved_and_short_source_is_rejected() {
        assert_eq!(read_snapshot(&mut Cursor::new(b"abc"), 3).unwrap(), b"abc");
        assert!(read_snapshot(&mut Cursor::new(b"ab"), 3).is_err());
    }

    #[test]
    fn impossible_reservation_is_an_error_not_a_capacity_panic() {
        assert!(read_snapshot(&mut Cursor::new(b""), usize::MAX).is_err());
    }

    struct InterruptedProbe {
        data: Cursor<Vec<u8>>,
        interrupted: bool,
    }
    impl Read for InterruptedProbe {
        fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
            if self.data.position() == self.data.get_ref().len() as u64 && !self.interrupted {
                self.interrupted = true;
                return Err(io::Error::from(ErrorKind::Interrupted));
            }
            self.data.read(out)
        }
    }

    #[test]
    fn interrupted_eof_probe_is_retried() {
        let mut reader = InterruptedProbe {
            data: Cursor::new(vec![1, 2]),
            interrupted: false,
        };
        assert_eq!(read_snapshot(&mut reader, 2).unwrap(), vec![1, 2]);
        assert!(reader.interrupted);
    }

    struct FailedProbe {
        data: Cursor<Vec<u8>>,
    }
    impl Read for FailedProbe {
        fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
            if self.data.position() == self.data.get_ref().len() as u64 {
                return Err(io::Error::from(ErrorKind::PermissionDenied));
            }
            self.data.read(out)
        }
    }

    #[test]
    fn probe_io_failure_is_not_treated_as_eof() {
        let mut reader = FailedProbe {
            data: Cursor::new(vec![1, 2]),
        };
        assert!(read_snapshot(&mut reader, 2).is_err());
    }
}
