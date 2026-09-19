//! Capture -> canonical journal -> externally sorted packet/range projection.
use crate::{
    bad,
    codec::{Decoder, Encoder},
    index::{self, Row},
    journal::{self, Quota, Reader, Writer},
    model::{Config, Key, SourceIdentity, TcpInput, Witness},
    state::{Decision, Store},
    Error, ErrorCode, Result,
};
use pcap_evidence::{
    capture::{CaptureReader, ParseMode},
    fragment::{FragmentOutcome, FragmentReassembler},
    provenance::EvidenceBytes,
    sha256::{self, Sha256},
    wire::{self, ChecksumPolicy, Scope, Transport},
    Limits,
};
use pcap_evidence_stream::network::{self, Decoded};
use std::{
    collections::BTreeMap,
    fs::{File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::Path,
    sync::atomic::{AtomicBool, Ordering},
};

#[derive(Default)]
pub struct Cancellation(pub AtomicBool);
impl Cancellation {
    pub fn cancel(&self) {
        self.0.store(true, Ordering::Relaxed);
    }
    pub fn check(&self) -> Result<()> {
        if self.0.load(Ordering::Relaxed) {
            Err(Error::new(
                ErrorCode::LimitExceeded,
                0,
                "cancelled",
                "analysis cancelled; no complete journal",
            ))
        } else {
            Ok(())
        }
    }
}
#[derive(Clone, Debug)]
pub struct Summary {
    pub source: SourceIdentity,
    pub packets: u64,
    pub tcp_records: u64,
    pub notices: u64,
    pub intervals: u64,
    pub disk_high_water: u64,
    pub sealed: bool,
}
impl Summary {
    pub fn json(&self) -> pcap_evidence::json::Json {
        use pcap_evidence::json::Json;
        Json::object([
            ("schema", "pcap-evidence.history-summary.v1".into()),
            ("source_sha256", sha256::hex(&self.source.sha256).into()),
            ("source_bytes", self.source.bytes.to_string().into()),
            ("packets", self.packets.to_string().into()),
            ("tcp_records", self.tcp_records.to_string().into()),
            ("notices", self.notices.to_string().into()),
            ("intervals", self.intervals.to_string().into()),
            (
                "logical_disk_high_water",
                self.disk_high_water.to_string().into(),
            ),
            ("journal_sealed", self.sealed.into()),
            (
                "history_scope",
                "retained_tcp_observations_and_generation_hypotheses".into(),
            ),
            ("complete_application_history", false.into()),
            ("endpoint_truth_established", false.into()),
        ])
    }
}
#[derive(Clone, Debug)]
pub struct PacketRow {
    pub frame: u64,
    pub record_offset: u64,
    pub data_offset: u64,
    pub cap: u32,
    pub original: u32,
    pub section: u32,
    pub interface: u32,
    pub link: u32,
    pub digest: [u8; 32],
}
impl PacketRow {
    pub const WIDTH: usize = 80;
    pub fn encode(&self) -> Vec<u8> {
        let mut e = Encoder::default();
        e.u64(self.frame);
        e.u64(self.record_offset);
        e.u64(self.data_offset);
        e.u32(self.cap);
        e.u32(self.original);
        e.u32(self.section);
        e.u32(self.interface);
        e.u32(self.link);
        e.u32(0);
        e.hash(&self.digest);
        e.0
    }
    pub fn decode(b: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(b);
        let (frame, record_offset, data_offset, cap, original, section, interface, link) = (
            d.u64()?,
            d.u64()?,
            d.u64()?,
            d.u32()?,
            d.u32()?,
            d.u32()?,
            d.u32()?,
            d.u32()?,
        );
        if d.u32()? != 0 {
            return Err(bad("packet_index", "reserved field"));
        }
        let digest = d.hash()?;
        d.finish()?;
        if frame == 0 || data_offset < record_offset {
            return Err(bad("packet_index", "invalid frame/offset"));
        }
        Ok(Self {
            frame,
            record_offset,
            data_offset,
            cap,
            original,
            section,
            interface,
            link,
            digest,
        })
    }
    pub fn get(file: &mut File, frame: u64) -> Result<Self> {
        let at = frame
            .checked_sub(1)
            .and_then(|x| x.checked_mul(Self::WIDTH as u64))
            .ok_or_else(|| Error::limit("packet_index"))?;
        file.seek(SeekFrom::Start(at))?;
        let mut b = [0; Self::WIDTH];
        file.read_exact(&mut b)?;
        let row = Self::decode(&b)?;
        if row.frame != frame {
            return Err(bad("packet_index", "ordinal mismatch"));
        }
        Ok(row)
    }
}
pub fn tcp_record(input: &TcpInput, decision: &Decision) -> Result<Vec<u8>> {
    let mut e = Encoder::default();
    e.bytes(&input.encode()?)?;
    e.bytes(&decision.encode()?)?;
    Ok(e.0)
}
pub fn decode_tcp_record(bytes: &[u8], c: &Config) -> Result<(TcpInput, Decision)> {
    let mut d = Decoder::new(bytes);
    let input = TcpInput::decode(d.bytes(c.max_record_bytes)?, c)?;
    let decision = Decision::decode(d.bytes(c.max_record_bytes)?, c)?;
    d.finish()?;
    Ok((input, decision))
}
struct Pipeline<'a> {
    journal: Writer,
    table: File,
    placements: File,
    states: Option<Store>,
    fragments: BTreeMap<Vec<String>, FragmentReassembler>,
    config: Config,
    quota: Quota,
    cancel: &'a Cancellation,
    summary: Summary,
}
impl Pipeline<'_> {
    fn notice(&mut self, reason: &str, frames: &[u64]) -> Result<()> {
        if reason.len() > 2048 || frames.len() > 4096 {
            return Err(Error::limit("history_notice"));
        }
        let mut e = Encoder::default();
        e.text(reason)?;
        e.u32(frames.len() as u32);
        for n in frames {
            e.u64(*n);
        }
        self.journal.append(journal::NOTICE, &e.0)?;
        self.summary.notices += 1;
        Ok(())
    }
    fn flush_fragments(&mut self) -> Result<()> {
        let maps = std::mem::take(&mut self.fragments);
        for (_, f) in maps {
            for n in f.finish() {
                self.notice(
                    n.code,
                    &n.packets.iter().map(|p| p.frame).collect::<Vec<_>>(),
                )?;
            }
        }
        Ok(())
    }
    fn expire(&mut self, frame: u64) -> Result<()> {
        let keys: Vec<_> = self.fragments.keys().cloned().collect();
        for key in keys {
            let f = self
                .fragments
                .get_mut(&key)
                .ok_or_else(|| bad("fragments", "missing slot"))?;
            let notices = f.expire(frame);
            for n in notices {
                self.notice(
                    n.code,
                    &n.packets.iter().map(|p| p.frame).collect::<Vec<_>>(),
                )?;
            }
        }
        Ok(())
    }
    fn layers(
        &mut self,
        decoded: Decoded,
        mut path: Vec<String>,
        frame: u64,
        when: Option<i128>,
        depth: usize,
    ) -> Result<()> {
        self.cancel.check()?;
        let (mut d, extra) = match decoded {
            Decoded::Ip(d, p) => (d, p),
            Decoded::Metadata { protocol, .. } => {
                self.notice(&format!("outside_tcp_history:{protocol}"), &[frame])?;
                return Ok(());
            }
        };
        if d.ip_checksum == wire::Checksum::Invalid {
            self.notice("invalid_ip_checksum_observed_not_repaired", &[frame])?;
        }
        path.extend(extra);
        if path.len() > 16 {
            return self.notice("tunnel_scope_limit", &[frame]);
        }
        if d.fragment.is_some() {
            if !self.fragments.contains_key(&path) {
                if self.fragments.len() >= 16 {
                    self.flush_fragments()?;
                    self.notice("fragment_context_budget_reset", &[frame])?;
                }
                let limits = Limits {
                    max_retained_payload: 1024 * 1024,
                    max_fragment_sets: 32,
                    max_fragments_per_set: 128,
                    ..Limits::default()
                };
                self.fragments
                    .insert(path.clone(), FragmentReassembler::new(limits));
            }
            let result = self
                .fragments
                .get_mut(&path)
                .ok_or_else(|| bad("fragments", "missing slot"))?
                .push(d, frame);
            d = match result {
                Ok(FragmentOutcome::Pending) => return Ok(()),
                Ok(FragmentOutcome::Complete(d, _)) => d,
                Ok(FragmentOutcome::Rejected(n)) => {
                    return self.notice(
                        n.code,
                        &n.packets.iter().map(|p| p.frame).collect::<Vec<_>>(),
                    )
                }
                Err(e) => {
                    if let Some(f) = self.fragments.remove(&path) {
                        for n in f.finish() {
                            self.notice(
                                n.code,
                                &n.packets.iter().map(|p| p.frame).collect::<Vec<_>>(),
                            )?;
                        }
                    }
                    return self.notice(&format!("fragment_budget_or_error:{e}"), &[frame]);
                }
            };
        }
        d = match network::normalize(d) {
            Ok(d) => d,
            Err(e) => return self.notice(&format!("network_normalization:{e}"), &[frame]),
        };
        if d.protocol == 17 {
            match wire::decode_transport(&d, ChecksumPolicy::Observe) {
                Ok(Transport::Udp(u)) if u.checksum == wire::Checksum::Invalid => {
                    self.notice("invalid_outer_udp_checksum_observed_not_repaired", &[frame])?
                }
                Err(e) => return self.notice(&format!("outer_udp_decode:{e}"), &[frame]),
                _ => {}
            }
        }
        match network::peel(&d) {
            Ok(Some((inner, hop))) => {
                if depth >= 4 {
                    return self.notice("tunnel_depth_limit", &[frame]);
                }
                path.push(format!("{}>{}:{}", d.source, d.destination, hop));
                return self.layers(inner, path, frame, when, depth + 1);
            }
            Err(e) => {
                return self.notice(&format!("tunnel_interpretation_unavailable:{e}"), &[frame])
            }
            Ok(None) => {}
        }
        if d.protocol != 6 {
            return self.notice("non_tcp_observation_retained_in_source", &[frame]);
        }
        let segment = match wire::decode_transport(&d, ChecksumPolicy::Observe) {
            Ok(Transport::Tcp(t)) => t,
            Ok(_) => return self.notice("transport_not_tcp", &[frame]),
            Err(e) => return self.notice(&format!("tcp_decode:{e}"), &[frame]),
        };
        let (a, b, direction) = if segment.source <= segment.destination {
            (segment.source, segment.destination, 0)
        } else {
            (segment.destination, segment.source, 1)
        };
        let key = Key {
            section: d.scope.section,
            interface: d.scope.interface,
            vlans: d.scope.vlans.clone(),
            tunnels: path,
            a,
            b,
        };
        let mut witnesses = Vec::new();
        for span in d.payload.spans() {
            let p = PacketRow::get(&mut self.table, span.packet.frame)?;
            if p.record_offset != span.packet.record_offset
                || span
                    .packet_start
                    .checked_add(span.end - span.start)
                    .is_none_or(|end| end > p.cap as usize)
            {
                return Err(bad(
                    "history_witness",
                    "source range outside indexed packet",
                ));
            }
            witnesses.push(Witness {
                start: u32::try_from(span.start).map_err(|_| Error::limit("span"))?,
                end: u32::try_from(span.end).map_err(|_| Error::limit("span"))?,
                frame: p.frame,
                record_offset: p.record_offset,
                packet_start: span.packet_start as u32,
                source_offset: p
                    .data_offset
                    .checked_add(span.packet_start as u64)
                    .ok_or_else(|| Error::limit("span"))?,
            });
        }
        let input = match TcpInput::new(
            key,
            direction,
            frame,
            when,
            d.payload.data().to_vec(),
            witnesses,
            &self.config,
        ) {
            Ok(p) => p,
            Err(e) => return self.notice(&format!("tcp_input:{e}"), &[frame]),
        };
        let mut decision = self
            .states
            .as_mut()
            .ok_or_else(|| bad("history_state", "state store finished"))?
            .ingest(&input)?;
        if segment.checksum == wire::Checksum::Invalid {
            decision
                .reasons
                .push("invalid_tcp_checksum_observed_not_repaired".into());
        }
        let (offset, digest) = self
            .journal
            .append(journal::TCP, &tcp_record(&input, &decision)?)?;
        self.summary.tcp_records += 1;
        if !input.payload().is_empty() {
            for p in &decision.placements {
                let end = p
                    .offset
                    .checked_add(input.payload().len() as i64)
                    .ok_or_else(|| Error::limit("sequence_span"))?;
                index::append(
                    &mut self.placements,
                    &Row {
                        generation: p.generation,
                        direction: p.direction,
                        selected: p.selected,
                        start: p.offset,
                        end,
                        record_offset: offset,
                        record_digest: digest,
                        ordinal: self.journal.count,
                    },
                    &self.quota,
                )?;
            }
        }
        Ok(())
    }
}
fn source_hash(path: &Path, c: &Config, cancel: &Cancellation) -> Result<SourceIdentity> {
    journal::regular(path)?;
    let mut f = File::open(path)?;
    let mut b = [0u8; 65536];
    let mut h = Sha256::new();
    let mut n = 0u64;
    loop {
        cancel.check()?;
        let k = f.read(&mut b)?;
        if k == 0 {
            break;
        }
        n = n
            .checked_add(k as u64)
            .ok_or_else(|| Error::limit("source"))?;
        if n > c.max_source_bytes {
            return Err(Error::limit("source"));
        }
        h.update(&b[..k]);
    }
    Ok(SourceIdentity {
        sha256: h.finalize(),
        bytes: n,
    })
}
/// Two streaming source passes. This does not allocate a capture-sized buffer or
/// call an external parser. Output is a new private workspace; partial workspaces
/// remain unsealed and can be inspected/recovered explicitly.
pub fn analyze_file(
    source: &Path,
    destination: &Path,
    config: Config,
    cancel: &Cancellation,
) -> Result<Summary> {
    config.validate()?;
    let identity = source_hash(source, &config, cancel)?;
    journal::new_workspace(destination)?;
    let q = journal::quota(config.max_disk_bytes);
    let writer = Writer::create(
        &destination.join("journal.bin"),
        identity.clone(),
        config.clone(),
        q.clone(),
    )?;
    let table = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(destination.join("packets.idx"))?;
    let placements = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination.join("placements.raw"))?;
    let states = Store::new(
        &destination.join("state"),
        config.clone(),
        identity.clone(),
        q.clone(),
    )?;
    let mut p = Pipeline {
        journal: writer,
        table,
        placements,
        states: Some(states),
        fragments: BTreeMap::new(),
        config: config.clone(),
        quota: q.clone(),
        cancel,
        summary: Summary {
            source: identity.clone(),
            packets: 0,
            tcp_records: 0,
            notices: 0,
            intervals: 0,
            disk_high_water: 0,
            sealed: false,
        },
    };
    let run = (|| -> Result<()> {
        let limits = Limits {
            max_input_bytes: usize::try_from(config.max_source_bytes)
                .map_err(|_| Error::limit("source"))?,
            max_records: usize::try_from(config.max_records)
                .map_err(|_| Error::limit("records"))?,
            ..Limits::default()
        };
        let mut reader = CaptureReader::new(File::open(source)?, limits, ParseMode::Strict)?;
        let mut hash = Sha256::new();
        let mut consumed = 0u64;
        while let Some(record) = reader.next_record()? {
            cancel.check()?;
            hash.update(record.raw());
            consumed = consumed
                .checked_add(record.raw().len() as u64)
                .ok_or_else(|| Error::limit("source"))?;
            if let Some((meta, data)) = record.packet() {
                p.expire(meta.frame)?;
                if meta.frame != p.summary.packets + 1 {
                    return Err(bad("history_frame", "noncontiguous packet numbering"));
                }
                let row = PacketRow {
                    frame: meta.frame,
                    record_offset: record.offset(),
                    data_offset: record
                        .offset()
                        .checked_add(meta.data_offset as u64)
                        .ok_or_else(|| Error::limit("offset"))?,
                    cap: meta.captured_len,
                    original: meta.original_len,
                    section: meta.section,
                    interface: meta.interface,
                    link: meta.link_type,
                    digest: sha256::digest(data),
                };
                let encoded = row.encode();
                q.borrow_mut().charge(encoded.len() as u64)?;
                p.table.seek(SeekFrom::End(0))?;
                p.table.write_all(&encoded)?;
                let mut body = Encoder(encoded);
                body.u64(record.raw().len() as u64);
                body.hash(&sha256::digest(record.raw()));
                if let Some(t) = meta.timestamp {
                    body.u8(1);
                    body.u64(t.ticks);
                    body.u8(t.resolution.to_pcapng()?);
                    body.i64(t.offset_seconds);
                } else {
                    body.u8(0);
                }
                p.journal.append(journal::PACKET, &body.0)?;
                p.summary.packets += 1;
                let raw = EvidenceBytes::from_packet(
                    data,
                    pcap_evidence::provenance::PacketId {
                        capture: identity.sha256,
                        frame: meta.frame,
                        record_offset: record.offset(),
                    },
                    0,
                );
                let scope = Scope {
                    section: meta.section,
                    interface: meta.interface,
                    vlans: Vec::new(),
                };
                match network::decode(meta.link_type, &raw, scope) {
                    Ok(d) => p.layers(
                        d,
                        Vec::new(),
                        meta.frame,
                        meta.timestamp.and_then(|t| t.unix_nanos().ok()),
                        0,
                    )?,
                    Err(e) => p.notice(&format!("network_decode:{e}"), &[meta.frame])?,
                }
                if p.summary.packets % config.checkpoint_records == 0 {
                    let mut e = Encoder::default();
                    e.u64(p.summary.packets);
                    e.u64(consumed);
                    e.hash(&p.journal.previous);
                    p.table.sync_all()?;
                    p.placements.sync_all()?;
                    p.journal.append(journal::CHECKPOINT, &e.0)?;
                }
            }
        }
        if (SourceIdentity {
            sha256: hash.finalize(),
            bytes: consumed,
        }) != identity
        {
            return Err(Error::new(
                ErrorCode::SourceMismatch,
                0,
                "source",
                "source changed between identity and analysis passes",
            ));
        }
        p.flush_fragments()?;
        p.states
            .take()
            .ok_or_else(|| bad("history_state", "missing store"))?
            .finish()?;
        p.table.sync_all()?;
        p.placements.sync_all()?;
        Ok(())
    })();
    if let Err(error) = run {
        let mut e = Encoder::default();
        e.text(&error.to_string())?;
        let _ = p.journal.append(journal::ABORT, &e.0);
        return Err(error);
    }
    // Windows requires closing the source placement handle before external sort.
    drop(p.placements);
    drop(p.table);
    cancel.check()?;
    let total = index::sort_checked(
        destination,
        config.sort_entries,
        config.merge_fan_in,
        &q,
        || cancel.check(),
    )?;
    cancel.check()?;
    let ranges = journal::hash_file(&destination.join("ranges.idx"), config.max_disk_bytes)?;
    let packets = journal::hash_file(&destination.join("packets.idx"), config.max_disk_bytes)?;
    let mut seal = Encoder::default();
    seal.u64(p.summary.packets);
    seal.u64(p.summary.tcp_records);
    seal.u64(p.summary.notices);
    seal.u64(total);
    seal.hash(&ranges.sha256);
    seal.u64(ranges.bytes);
    seal.hash(&packets.sha256);
    seal.u64(packets.bytes);
    p.journal.append(journal::SEAL, &seal.0)?;
    journal::sync_directory(destination)?;
    p.summary.intervals = total;
    p.summary.disk_high_water = q.borrow().peak;
    p.summary.sealed = true;
    Ok(p.summary)
}
/// Semantic verification rebuilds BOTH journal and indexes from the original
/// source into a caller-chosen NEW workspace. It does not trust a rehashed report.
pub fn verify_file(
    source: &Path,
    workspace: &Path,
    replay: &Path,
    cancel: &Cancellation,
) -> Result<Summary> {
    let mut old = Reader::open(&workspace.join("journal.bin"))?;
    while old.next_record()?.is_some() {}
    if !old.sealed {
        return Err(bad("history_verify", "unsealed input journal"));
    }
    let summary = analyze_file(source, replay, old.header.config.clone(), cancel)?;
    for name in ["journal.bin", "ranges.idx", "packets.idx"] {
        cancel.check()?;
        if journal::hash_file(&workspace.join(name), old.header.config.max_disk_bytes)?
            != journal::hash_file(&replay.join(name), old.header.config.max_disk_bytes)?
        {
            return Err(bad(
                "history_replay",
                "source-derived canonical projection mismatch",
            ));
        }
    }
    Ok(summary)
}
/// Restart by replay, not by trusting derived hot-state files. A torn final field
/// requires explicit authorization. Interior corruption is always an error.
pub fn recover_file(
    source: &Path,
    old: &Path,
    new: &Path,
    allow_torn_tail: bool,
    cancel: &Cancellation,
) -> Result<Summary> {
    let mut reader = Reader::open(&old.join("journal.bin"))?;
    let mut prefix = reader.header.bytes;
    loop {
        match reader.next_record() {
            Ok(Some(r)) => {
                if r.kind == journal::ABORT || r.kind == journal::SEAL {
                    break;
                }
                prefix = reader.position;
            }
            Ok(None) => break,
            Err(e) if allow_torn_tail && e.code == ErrorCode::Truncated => break,
            Err(e) => return Err(e),
        }
    }
    if source_hash(source, &reader.header.config, cancel)? != reader.header.source {
        return Err(bad("history_recovery", "changed source"));
    }
    let result = analyze_file(source, new, reader.header.config.clone(), cancel)?;
    let mut a = File::open(old.join("journal.bin"))?.take(prefix);
    let mut b = File::open(new.join("journal.bin"))?.take(prefix);
    if journal::hash_reader(&mut a, prefix)? != journal::hash_reader(&mut b, prefix)? {
        return Err(bad(
            "history_recovery",
            "new replay does not reproduce valid original prefix",
        ));
    }
    Ok(result)
}
