#![no_main]
use libfuzzer_sys::fuzz_target;
use pcap_evidence_product::protocols::Protocol;
use pcap_evidence::{Limits, capture::{CaptureIter, ParseMode}};
fuzz_target!(|bytes: &[u8]| {
    if bytes.len() > 65536 { return; }
    for &protocol in Protocol::ALL {
        if !protocol.compiled() { continue; }
        let first=protocol.decode(bytes); let second=protocol.decode(bytes);
        match (first, second) {
            (Ok(a),Ok(b))=>{assert_eq!(a,b);assert!(a.consumed>0 && a.consumed<=bytes.len());},
            (Err(a),Err(b))=>assert_eq!(a.to_string(),b.to_string()),
            _=>panic!("nondeterministic parser outcome"),
        }
    }
    let limits=Limits{max_input_bytes:65536,max_records:1024,..Limits::default()};
    for mode in [ParseMode::Strict,ParseMode::Evidence] {
        if let Ok(iter)=CaptureIter::new(bytes,limits.clone(),mode){
            for record in iter {if record.is_err(){break;}}
        }
    }
});
