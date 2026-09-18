//! Incremental Internet checksum with correct odd-byte handling across updates.
//!
//! Updates do not allocate or copy the complete packet. RFC 1071 one's-complement
//! addition applies to the concatenation of the supplied byte slices, not to
//! each slice independently; an odd final byte is carried into the next update.
#[derive(Clone, Debug, Default)]
pub struct InternetChecksum {
    sum: u32,
    high_byte: Option<u8>,
}
impl InternetChecksum {
    pub fn new() -> Self {
        Self::default()
    }

    fn add_word(&mut self, word: u16) {
        // Folding after every addition bounds sum independently of input length.
        self.sum += u32::from(word);
        self.sum = (self.sum & 0xffff) + (self.sum >> 16);
    }

    pub fn update(&mut self, mut bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        if let Some(high) = self.high_byte.take() {
            self.add_word(u16::from_be_bytes([high, bytes[0]]));
            bytes = &bytes[1..];
        }
        let mut pairs = bytes.chunks_exact(2);
        for pair in &mut pairs {
            self.add_word(u16::from_be_bytes([pair[0], pair[1]]));
        }
        self.high_byte = pairs.remainder().first().copied();
    }

    /// Complements the sum, padding an odd final byte with a low-order zero.
    /// This borrows rather than consumes, so callers can snapshot the checksum.
    pub fn finish(&self) -> u16 {
        let mut sum = self.sum;
        if let Some(high) = self.high_byte {
            sum += u32::from(high) << 8;
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !(sum as u16)
    }
}
