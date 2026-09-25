// Included inside query.rs so source/index ownership does not leak through a
// public raw-file API. Typed pieces reuse the existing verified range query.
#[derive(Clone,Debug)]
pub struct EvidencePiece {
    pub start:i64,
    pub end:i64,
    pub status:String,
    pub bytes:Option<pcap_evidence::provenance::EvidenceBytes>,
}
#[derive(Clone,Debug)]
pub struct EvidenceRange {pub pieces:Vec<EvidencePiece>,pub research:Json}
fn typed_field<'a>(v:&'a Json,key:&str)->Result<&'a Json>{match v{Json::Object(o)=>o.iter().find(|(k,_)|*k==key).map(|(_,v)|v).ok_or_else(||bad("typed_range","missing field")),_=>Err(bad("typed_range","not an object"))}}
fn typed_u(v:&Json)->Result<u64>{match v{Json::Number(n)=>Ok(*n),Json::String(s)=>s.parse().map_err(|_|bad("typed_range","bad unsigned integer")),_=>Err(bad("typed_range","not integer"))}}
fn typed_i(v:&Json)->Result<i64>{match v{Json::String(s)=>s.parse().map_err(|_|bad("typed_range","bad signed integer")),_=>Err(bad("typed_range","not signed string"))}}
fn typed_array(v:&Json)->Result<&[Json]>{match v{Json::Array(v)=>Ok(v),_=>Err(bad("typed_range","not array"))}}
impl History{
    pub fn evidence_range(&mut self,generation:[u8;32],direction:u8,start:i64,end:i64)->Result<EvidenceRange>{
        let research=self.range(generation,direction,start,end)?;
        let observations=typed_array(typed_field(&research,"observations")?)?;
        let mut pieces=Vec::new();let mut copied=0usize;
        for p in typed_array(typed_field(&research,"pieces")?)?{
            let a=typed_i(typed_field(p,"start")?)?;let b=typed_i(typed_field(p,"end")?)?;
            let status=match typed_field(p,"status")?{Json::String(v)=>v.clone(),_=>return Err(bad("typed_range","bad status"))};
            let mut bytes=None;
            if status=="candidate"{
                let id=typed_u(typed_array(typed_field(p,"observation_ids")?)?.first().ok_or_else(||bad("typed_range","no source observation"))?)? as usize;
                let observation=observations.get(id).ok_or_else(||bad("typed_range","observation outside report"))?;
                let origin=typed_i(typed_field(observation,"start")?)?;
                let header=typed_u(typed_field(observation,"tcp_header_bytes")?)?;
                let raw_start=header.checked_add(u64::try_from(a-origin).map_err(|_|bad("typed_range","negative offset"))?).ok_or_else(||Error::limit("typed_offset"))?;
                let raw_end=raw_start.checked_add(u64::try_from(b-a).map_err(|_|bad("typed_range","negative extent"))?).ok_or_else(||Error::limit("typed_offset"))?;
                let mut out=pcap_evidence::provenance::EvidenceBytes::default();
                for w in typed_array(typed_field(observation,"witnesses")?)?{
                    let lo=typed_u(typed_field(w,"raw_start")?)?.max(raw_start);let hi=typed_u(typed_field(w,"raw_end")?)?.min(raw_end);if hi<=lo{continue;}
                    let delta=lo-typed_u(typed_field(w,"raw_start")?)?;
                    let frame=typed_u(typed_field(w,"frame")?)?;let packet=PacketRow::get(&mut self.packets,frame)?;
                    let packet_start=typed_u(typed_field(w,"packet_start")?)?.checked_add(delta).ok_or_else(||Error::limit("typed_offset"))?;
                    let offset=typed_u(typed_field(w,"source_offset")?)?.checked_add(delta).ok_or_else(||Error::limit("typed_offset"))?;
                    if packet.data_offset.checked_add(packet_start)!=Some(offset)||packet_start.checked_add(hi-lo).is_none_or(|n|n>u64::from(packet.cap)){return Err(bad("typed_range","witness outside packet"));}
                    let n=usize::try_from(hi-lo).map_err(|_|Error::limit("typed_range"))?;copied=copied.checked_add(n).filter(|n|*n<=self.config.max_query_bytes).ok_or_else(||Error::limit("typed_range_bytes"))?;
                    let mut raw=vec![0;n];self.source.seek(SeekFrom::Start(offset))?;self.source.read_exact(&mut raw)?;
                    let part=pcap_evidence::provenance::EvidenceBytes::from_packet(&raw,pcap_evidence::provenance::PacketId{capture:self.identity.sha256,frame,record_offset:packet.record_offset},usize::try_from(packet_start).map_err(|_|Error::limit("typed_packet_start"))?);
                    out.append(&part,self.config.max_query_bytes)?;
                }
                if out.len()!=usize::try_from(b-a).map_err(|_|Error::limit("typed_extent"))?||typed_field(p,"bytes_hex")?!=&Json::String(sha256::hex(out.data())){return Err(bad("typed_range","typed witnesses disagree with verified range bytes"));}
                bytes=Some(out);
            }
            pieces.push(EvidencePiece{start:a,end:b,status,bytes});
        }Ok(EvidenceRange{pieces,research})
    }
    /// Streaming index scan with a caller-visible work cap. No capture-sized
    /// allocations; a limit failure cannot be treated as a shortened extent.
    pub fn extent(&mut self,generation:[u8;32],direction:u8,max_rows:u64)->Result<Option<(i64,i64)>>{
        if direction>1||max_rows==0{return Err(Error::limit("extent_scan"));}let mut at=self.index.lower_bound(generation,direction,i64::MIN)?;let mut found:Option<(i64,i64)>=None;let mut scanned=0;
        while at<self.index.count{let row=self.index.at(at)?;if row.generation!=generation||row.direction!=direction{break;}scanned+=1;if scanned>max_rows{return Err(Error::limit("extent_scan"));}found=Some(match found{Some((a,b))=>(a.min(row.start),b.max(row.end)),None=>(row.start,row.end)});at+=1;}Ok(found)
    }
}
