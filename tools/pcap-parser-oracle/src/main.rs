//! Independent container cross-check; deliberately no pcap-evidence dependency.
//! Comparisons cover frame count/captured length/original length, not semantic truth.
#![forbid(unsafe_code)]
use pcap_parser::{create_reader,Block,PcapBlockOwned,PcapError};
use std::{fs::File,io::{self,BufWriter,Write}};
fn bad(message:impl Into<String>)->io::Error{io::Error::new(io::ErrorKind::InvalidData,message.into())}
fn run()->Result<(),Box<dyn std::error::Error>>{
    let args:Vec<_>=std::env::args_os().skip(1).collect();
    if args.len()==1 && args[0]=="--version"{println!("pcap-parser-independent-oracle 0.1.0; pcap-parser 0.17.0");return Ok(());}
    if args.len()!=1{return Err(bad("usage: pcap-parser-independent-oracle CAPTURE").into());}
    let file=File::open(&args[0])?;
    let mut reader=create_reader(16*1024*1024,file).map_err(|e|bad(format!("create reader: {e:?}")))?;
    let mut output=BufWriter::new(io::stdout().lock());let mut frame=0u64;let mut first_snaplen=None;
    loop{
        match reader.next(){
            Ok((consumed,block))=>{
                let lengths=match block{
                    PcapBlockOwned::Legacy(packet)=>Some((packet.caplen,packet.origlen)),
                    PcapBlockOwned::LegacyHeader(_)=>None,
                    PcapBlockOwned::NG(block)=>match block{
                        Block::SectionHeader(_)=>{first_snaplen=None;None},
                        Block::InterfaceDescription(interface)=>{if first_snaplen.is_none(){first_snaplen=Some(interface.snaplen);}None},
                        Block::EnhancedPacket(packet)=>Some((packet.caplen,packet.origlen)),
                        Block::SimplePacket(packet)=>{
                            let snap=first_snaplen.ok_or_else(||bad("SPB before IDB"))?;
                            let cap=if snap==0{packet.origlen}else{packet.origlen.min(snap)};
                            if cap as usize>packet.data.len(){return Err(bad("SPB captured length exceeds data").into());}
                            Some((cap,packet.origlen))
                        },
                        _=>None,
                    },
                };
                if let Some((captured,original))=lengths{
                    frame=frame.checked_add(1).ok_or_else(||bad("frame overflow"))?;
                    writeln!(output,"{{\"frame\":\"{frame}\",\"captured_length\":{captured},\"original_length\":{original}}}")?;
                }
                reader.consume(consumed);
            },
            Err(PcapError::Eof)=>break,
            Err(PcapError::Incomplete(_))=>{
                if reader.reader_exhausted(){return Err(bad("truncated capture").into());}
                let before=reader.data().len();reader.refill().map_err(|e|bad(format!("refill: {e:?}")))?;
                if reader.data().len()==before && !reader.reader_exhausted(){return Err(bad("record exceeds fixed 16 MiB oracle buffer").into());}
            },
            Err(error)=>return Err(bad(format!("parse: {error:?}")).into()),
        }
    }
    output.flush()?;Ok(())
}
fn main(){if let Err(error)=run(){eprintln!("{error}");std::process::exit(1);}}
