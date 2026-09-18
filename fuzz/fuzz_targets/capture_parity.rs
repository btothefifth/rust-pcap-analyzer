#![no_main]
mod support;
use libfuzzer_sys::fuzz_target;
use pcap_evidence::capture::{CaptureIter, CaptureReader, ParseMode};
use std::io::{self, Read};
struct Fragmented<'a> {
    rest: &'a [u8],
    step: usize,
    calls: usize,
}
impl Read for Fragmented<'_> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        self.calls += 1;
        if self.calls % 3 == 0 {
            return Err(io::ErrorKind::Interrupted.into());
        }
        let n = self.step.min(output.len()).min(self.rest.len());
        output[..n].copy_from_slice(&self.rest[..n]);
        self.rest = &self.rest[n..];
        Ok(n)
    }
}
fuzz_target!(|data: &[u8]| {
    let limits = support::limits();
    if data.len() > limits.max_input_bytes {
        return;
    }
    for mode in [ParseMode::Strict, ParseMode::Evidence] {
        let mut borrowed = CaptureIter::new(data, limits.clone(), mode).unwrap();
        let input = Fragmented {
            rest: data,
            step: 1 + usize::from(data.first().copied().unwrap_or(0) % 17),
            calls: 0,
        };
        let mut streaming = CaptureReader::new(input, limits.clone(), mode).unwrap();
        loop {
            match (borrowed.next(), streaming.next()) {
                (None, None) => break,
                (Some(Ok(a)), Some(Ok(b))) => assert_eq!(a.into_owned(), b),
                (Some(Err(a)), Some(Err(b))) => {
                    assert_eq!(a.code, b.code);
                    assert!(borrowed.next().is_none());
                    assert!(streaming.next().is_none());
                    break;
                }
                _ => panic!("borrowed/streaming framing or termination divergence"),
            }
        }
    }
});
