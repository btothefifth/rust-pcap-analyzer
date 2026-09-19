//! Bounded interval queries. All conflicting bytes and placement hypotheses survive.
use crate::{
    bad,
    codec::Decoder,
    index::{Index, Row},
    journal::{self, Reader},
    model::{Config, SourceIdentity, TcpInput},
    pipeline::{decode_tcp_record, PacketRow},
    state::Decision,
    Error, Result,
};
use pcap_evidence::{json::Json, sha256};
use std::{
    collections::BTreeSet,
    fs::File,
    io::{Read, Seek, SeekFrom},
    path::Path,
};

pub struct History {
    source: File,
    journal: Reader,
    index: Index,
    packets: File,
    pub config: Config,
    pub identity: SourceIdentity,
}
impl History {
    /// Checks complete chain and source/index hashes, NOT normative correctness or
    /// semantic replay. Use pipeline::verify_file for same-engine source-derived replay.
    pub fn open(source: &Path, workspace: &Path) -> Result<Self> {
        let mut reader = Reader::open(&workspace.join("journal.bin"))?;
        let config = reader.header.config.clone();
        if journal::hash_file(source, config.max_source_bytes)? != reader.header.source {
            return Err(bad("history_source", "source identity mismatch"));
        }
        let mut seal = None;
        while let Some(r) = reader.next_record()? {
            if r.kind == journal::SEAL {
                seal = Some(r.body);
            }
        }
        let body = seal.ok_or_else(|| {
            bad(
                "history_incomplete",
                "no complete seal; do not present partial history as verified",
            )
        })?;
        let mut d = Decoder::new(&body);
        let packet_count = d.u64()?;
        let _tcp = d.u64()?;
        let _notices = d.u64()?;
        let intervals = d.u64()?;
        let range_hash = d.hash()?;
        let range_len = d.u64()?;
        let packet_hash = d.hash()?;
        let packet_len = d.u64()?;
        d.finish()?;
        let range = journal::hash_file(&workspace.join("ranges.idx"), config.max_disk_bytes)?;
        let packet = journal::hash_file(&workspace.join("packets.idx"), config.max_disk_bytes)?;
        if range.sha256 != range_hash
            || range.bytes != range_len
            || packet.sha256 != packet_hash
            || packet.bytes != packet_len
            || range_len
                != intervals
                    .checked_mul(crate::index::WIDTH as u64)
                    .ok_or_else(|| Error::limit("index_count"))?
            || packet_len
                != packet_count
                    .checked_mul(PacketRow::WIDTH as u64)
                    .ok_or_else(|| Error::limit("packet_count"))?
        {
            return Err(bad(
                "history_index",
                "sealed index identities/counts disagree",
            ));
        }
        let mut index = Index::open(&workspace.join("ranges.idx"))?;
        let mut previous = None;
        for n in 0..index.count {
            let row = index.at(n)?;
            if previous.as_ref().is_some_and(|old| old >= &row) {
                return Err(bad("history_index", "index is not sorted"));
            }
            previous = Some(row);
        }
        let identity = reader.header.source.clone();
        Ok(Self {
            source: File::open(source)?,
            journal: reader,
            index,
            packets: File::open(workspace.join("packets.idx"))?,
            config,
            identity,
        })
    }
    fn source_witnesses(&mut self, input: &TcpInput, work: &mut u64) -> Result<()> {
        for w in &input.witnesses {
            let p = PacketRow::get(&mut self.packets, w.frame)?;
            let n = (w.end - w.start) as usize;
            if p.record_offset != w.record_offset
                || u64::from(w.packet_start) + n as u64 > u64::from(p.cap)
                || p.data_offset.checked_add(u64::from(w.packet_start)) != Some(w.source_offset)
            {
                return Err(bad("history_witness", "witness outside canonical packet"));
            }
            *work = work
                .checked_add(n as u64)
                .ok_or_else(|| Error::limit("query_work"))?;
            if *work > self.config.max_query_work {
                return Err(Error::limit("query_work"));
            }
            let mut bytes = vec![0; n];
            self.source.seek(SeekFrom::Start(w.source_offset))?;
            self.source.read_exact(&mut bytes)?;
            if input.raw[w.start as usize..w.end as usize] != bytes {
                return Err(bad(
                    "history_witness",
                    "stored transport bytes disagree with original source",
                ));
            }
        }
        Ok(())
    }
    pub fn generations(&mut self, after: Option<[u8; 32]>, limit: usize) -> Result<Vec<[u8; 32]>> {
        if !(1..=200).contains(&limit) {
            return Err(Error::limit("generation_page"));
        }
        let mut at = match after {
            Some(id) => self.index.lower_bound(id, 1, i64::MAX)?,
            None => 0,
        };
        let mut out = Vec::new();
        let mut seen = 0u64;
        while at < self.index.count && out.len() < limit {
            let row = self.index.at(at)?;
            at += 1;
            seen += 1;
            if seen > self.config.max_query_intervals as u64 {
                return Err(Error::limit("generation_scan"));
            }
            if after.is_some_and(|id| row.generation <= id) {
                continue;
            }
            if out.last() != Some(&row.generation) {
                out.push(row.generation);
            }
            // Jump over all intervals for this generation rather than scan it.
            at = self.index.lower_bound(row.generation, 1, i64::MAX)?.max(at);
        }
        Ok(out)
    }
    pub fn range(
        &mut self,
        generation: [u8; 32],
        direction: u8,
        start: i64,
        end: i64,
    ) -> Result<Json> {
        let size = end
            .checked_sub(start)
            .filter(|n| *n > 0)
            .ok_or_else(|| bad("query_range", "positive ordered range required"))?;
        if direction > 1 || size as u64 > self.config.max_query_bytes as u64 {
            return Err(Error::limit("query_bytes"));
        }
        let low = start.saturating_sub(65535);
        let mut at = self.index.lower_bound(generation, direction, low)?;
        let mut observations = Vec::<(Row, TcpInput, Decision)>::new();
        let mut work = 0u64;
        let mut boundaries = BTreeSet::from([start, end]);
        while at < self.index.count {
            let row = self.index.at(at)?;
            at += 1;
            if row.generation != generation || row.direction != direction || row.start >= end {
                break;
            }
            if row.end <= start {
                continue;
            }
            if observations.len() >= self.config.max_query_intervals {
                return Err(Error::limit("query_intervals"));
            }
            let record = self.journal.indexed(row.record_offset, row.record_digest)?;
            if record.kind != journal::TCP || record.sequence != row.ordinal {
                return Err(bad("history_index", "index targets wrong record"));
            }
            work = work
                .checked_add(record.body.len() as u64)
                .ok_or_else(|| Error::limit("query_work"))?;
            if work > self.config.max_query_work {
                return Err(Error::limit("query_work"));
            }
            let (input, decision) = decode_tcp_record(&record.body, &self.config)?;
            if row.end - row.start != input.payload().len() as i64
                || !decision.placements.iter().any(|p| {
                    p.generation == generation
                        && p.direction == direction
                        && p.offset == row.start
                        && p.selected == row.selected
                })
            {
                return Err(bad(
                    "history_index",
                    "index placement is not emitted by journal decision",
                ));
            }
            self.source_witnesses(&input, &mut work)?;
            boundaries.insert(row.start.max(start));
            boundaries.insert(row.end.min(end));
            observations.push((row, input, decision));
        }
        let cuts: Vec<_> = boundaries.into_iter().collect();
        let mut pieces = Vec::new();
        let mut references = 0usize;
        for pair in cuts.windows(2) {
            let (a, b) = (pair[0], pair[1]);
            let mut selected: Option<&[u8]> = None;
            let mut conflict = false;
            let mut uncertain = false;
            let mut ids = Vec::new();
            for (i, (row, input, _decision)) in observations.iter().enumerate() {
                work = work
                    .checked_add(1)
                    .ok_or_else(|| Error::limit("query_work"))?;
                if work > self.config.max_query_work {
                    return Err(Error::limit("query_work"));
                }
                if row.start <= a && row.end >= b {
                    let raw = &input.payload()[(a - row.start) as usize..(b - row.start) as usize];
                    work = work
                        .checked_add(raw.len() as u64)
                        .ok_or_else(|| Error::limit("query_work"))?;
                    if work > self.config.max_query_work {
                        return Err(Error::limit("query_work"));
                    }
                    if selected.is_some_and(|old| old != raw) {
                        conflict = true;
                    }
                    selected.get_or_insert(raw);
                    uncertain |= !row.selected;
                    references += 1;
                    if references > self.config.max_query_intervals.saturating_mul(4) {
                        return Err(Error::limit("query_evidence_references"));
                    }
                    ids.push(Json::from(i));
                }
            }
            let status = if selected.is_none() {
                "gap"
            } else if conflict {
                "conflicting_bytes"
            } else if uncertain {
                "ambiguous_sequence_placement"
            } else {
                "candidate"
            };
            pieces.push(Json::object([
                ("start", a.to_string().into()),
                ("end", b.to_string().into()),
                ("status", status.into()),
                ("observation_ids", Json::Array(ids)),
                (
                    "bytes_hex",
                    if conflict || uncertain {
                        Json::Null
                    } else {
                        selected.map_or(Json::Null, |bytes| sha256::hex(bytes).into())
                    },
                ),
            ]));
        }
        let evidence = observations
            .iter()
            .enumerate()
            .map(|(i, (row, input, decision))| {
                Json::object([
                    ("id", i.into()),
                    ("journal_sequence", row.ordinal.to_string().into()),
                    ("packet", input.frame.to_string().into()),
                    ("start", row.start.to_string().into()),
                    ("end", row.end.to_string().into()),
                    ("placement_selected", row.selected.into()),
                    ("policy_assumption", decision.policy_assumption.into()),
                    (
                        "decision_reasons",
                        Json::array(decision.reasons.iter().cloned().map(Json::from)),
                    ),
                    ("state_before_sha256", sha256::hex(&decision.before).into()),
                    ("state_after_sha256", sha256::hex(&decision.after).into()),
                    ("tcp_header_bytes", input.header_bytes.into()),
                    (
                        "payload_sha256",
                        sha256::hex(&sha256::digest(input.payload())).into(),
                    ),
                    (
                        "witnesses",
                        Json::array(input.witnesses.iter().map(|w| {
                            Json::object([
                                ("frame", w.frame.to_string().into()),
                                ("source_offset", w.source_offset.to_string().into()),
                                ("packet_start", w.packet_start.into()),
                                ("raw_start", w.start.into()),
                                ("raw_end", w.end.into()),
                            ])
                        })),
                    ),
                ])
            });
        let result = Json::object([
            ("schema", "pcap-evidence.history-range.v1".into()),
            ("source_sha256", sha256::hex(&self.identity.sha256).into()),
            ("generation", sha256::hex(&generation).into()),
            ("direction", direction.into()),
            ("integrity_checked", true.into()),
            ("semantic_replay_verified", false.into()),
            ("pieces", Json::Array(pieces)),
            ("observations", Json::array(evidence)),
        ]);
        result.encode_bounded(self.config.max_record_bytes)?;
        Ok(result)
    }
}
