#![no_main]
use libfuzzer_sys::fuzz_target;
use pcap_evidence_history::{Config,EpochPolicy,Key,SourceIdentity,TcpInput,Witness};
use pcap_evidence_history::state::TupleState;
use pcap_evidence::wire::Endpoint;
fuzz_target!(|data: &[u8]| {
    let key=Key{section:0,interface:0,vlans:vec![],tunnels:vec![],
        a:Endpoint{address:"192.0.2.1".parse().unwrap(),port:1000},
        b:Endpoint{address:"192.0.2.2".parse().unwrap(),port:2000}};
    let source=SourceIdentity{sha256:[0;32],bytes:65536};
    let c=Config{max_generations:8,max_epoch_candidates:8,sequence_horizon:1_000_000_000,
        epoch_policy:if data.first().is_some_and(|x|x&1!=0){EpochPolicy::NearestFrontier}else{EpochPolicy::StrictAlternatives},..Config::default()};
    let mut a=TupleState::new(key.clone());let mut b=TupleState::new(key.clone());
    for (i,chunk) in data.chunks(32).take(128).enumerate() {
        if chunk.len()<12{break;}
        let dir=chunk[0]&1;let mut raw=vec![0;20];
        let (src,dst)=if dir==0{(1000u16,2000u16)}else{(2000,1000)};
        raw[..2].copy_from_slice(&src.to_be_bytes());raw[2..4].copy_from_slice(&dst.to_be_bytes());
        raw[4..12].copy_from_slice(&chunk[1..9]);raw[12]=0x50;raw[13]=chunk[9]&0x17;
        raw[14..16].copy_from_slice(&chunk[10..12]);raw.extend_from_slice(&chunk[12..]);
        let frame=i as u64+1;let span=Witness{start:0,end:raw.len()as u32,frame,record_offset:0,packet_start:0,source_offset:0};
        let input=TcpInput::new(key.clone(),dir,frame,Some(i128::from(chunk[0])),raw,vec![span],&c).unwrap();
        let before=a.encode().unwrap();let r=a.ingest(&input,&source,&c);let s=b.ingest(&input,&source,&c);
        assert_eq!(r,s);assert_eq!(a,b);
        if r.is_err(){assert_eq!(before,a.encode().unwrap());}
    }
});
