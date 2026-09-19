//! Conservative generation and sequence hypotheses. No vote chooses stream bytes.
use crate::{
    bad,
    codec::{Decoder, Encoder},
    journal::{self, Quota},
    model::{Config, EpochPolicy, Key, SourceIdentity, TcpInput, MODULUS},
    Error, Result,
};
use pcap_evidence::sha256;
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Generation {
    pub id: [u8; 32],
    pub birth: u64,
    pub syn: [Option<u32>; 2],
    pub anchor: [Option<u32>; 2],
    pub low: [i64; 2],
    pub high: [i64; 2],
    pub fin: [Option<i64>; 2],
    pub reset: bool,
    pub midstream: bool,
    pub last_time: Option<i128>,
}
impl Generation {
    pub fn closed(&self) -> bool {
        self.reset || self.fin.iter().all(Option::is_some)
    }
    fn encode(&self, e: &mut Encoder) {
        e.hash(&self.id);
        e.u64(self.birth);
        for x in self.syn {
            e.option_u32(x);
        }
        for x in self.anchor {
            e.option_u32(x);
        }
        for x in self.low {
            e.i64(x);
        }
        for x in self.high {
            e.i64(x);
        }
        for x in self.fin {
            e.option_i64(x);
        }
        e.u8(u8::from(self.reset));
        e.u8(u8::from(self.midstream));
        e.option_i128(self.last_time);
    }
    fn decode(d: &mut Decoder<'_>) -> Result<Self> {
        Ok(Self {
            id: d.hash()?,
            birth: d.u64()?,
            syn: [d.option_u32()?, d.option_u32()?],
            anchor: [d.option_u32()?, d.option_u32()?],
            low: [d.i64()?, d.i64()?],
            high: [d.i64()?, d.i64()?],
            fin: [d.option_i64()?, d.option_i64()?],
            reset: d.boolean()?,
            midstream: d.boolean()?,
            last_time: d.option_i128()?,
        })
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Placement {
    pub generation: [u8; 32],
    pub direction: u8,
    pub offset: i64,
    pub selected: bool,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Decision {
    pub before: [u8; 32],
    pub after: [u8; 32],
    pub placements: Vec<Placement>,
    pub reasons: Vec<String>,
    pub policy_assumption: bool,
}
impl Decision {
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut e = Encoder::default();
        e.hash(&self.before);
        e.hash(&self.after);
        e.u8(u8::from(self.policy_assumption));
        e.u32(
            u32::try_from(self.placements.len()).map_err(|_| Error::limit("history_candidates"))?,
        );
        for p in &self.placements {
            e.hash(&p.generation);
            e.u8(p.direction);
            e.i64(p.offset);
            e.u8(u8::from(p.selected));
        }
        e.u32(u32::try_from(self.reasons.len()).map_err(|_| Error::limit("history_reasons"))?);
        for s in &self.reasons {
            e.text(s)?;
        }
        Ok(e.0)
    }
    pub fn decode(b: &[u8], c: &Config) -> Result<Self> {
        let mut d = Decoder::new(b);
        let before = d.hash()?;
        let after = d.hash()?;
        let policy_assumption = d.boolean()?;
        let n = d.u32()? as usize;
        if n > c.max_generations.saturating_mul(c.max_epoch_candidates) {
            return Err(Error::limit("history_candidates"));
        }
        let mut placements = Vec::with_capacity(n);
        for _ in 0..n {
            let p = Placement {
                generation: d.hash()?,
                direction: d.u8()?,
                offset: d.i64()?,
                selected: d.boolean()?,
            };
            if p.direction > 1 {
                return Err(bad("history_direction", "invalid direction"));
            }
            placements.push(p);
        }
        let n = d.u32()? as usize;
        if n > 32 {
            return Err(Error::limit("history_reasons"));
        }
        let reasons = (0..n).map(|_| d.text(256)).collect::<Result<_>>()?;
        d.finish()?;
        Ok(Self {
            before,
            after,
            placements,
            reasons,
            policy_assumption,
        })
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TupleState {
    pub key: Key,
    pub generations: Vec<Generation>,
}
impl TupleState {
    pub fn new(key: Key) -> Self {
        Self {
            key,
            generations: Vec::new(),
        }
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut e = Encoder::default();
        e.bytes(&self.key.encode()?)?;
        e.u32(u32::try_from(self.generations.len()).map_err(|_| Error::limit("generations"))?);
        for g in &self.generations {
            g.encode(&mut e);
        }
        Ok(e.0)
    }
    pub fn decode(b: &[u8], c: &Config) -> Result<Self> {
        let mut d = Decoder::new(b);
        let key = Key::decode(d.bytes(10000)?)?;
        let n = d.u32()? as usize;
        if n > c.max_generations {
            return Err(Error::limit("generations"));
        }
        let generations = (0..n)
            .map(|_| Generation::decode(&mut d))
            .collect::<Result<Vec<_>>>()?;
        d.finish()?;
        if generations
            .iter()
            .any(|g| g.birth == 0 || (0..2).any(|i| g.low[i] > g.high[i]))
        {
            return Err(bad("history_state", "invalid generation bounds"));
        }
        Ok(Self { key, generations })
    }
    fn create(&mut self, p: &TcpInput, s: &SourceIdentity, c: &Config) -> Result<usize> {
        if self.generations.len() >= c.max_generations {
            return Err(Error::limit("generations_per_tuple"));
        }
        let mut seed = Encoder::default();
        seed.text("pcap-evidence/history-generation/v1")?;
        seed.hash(&s.sha256);
        seed.bytes(&self.key.encode()?)?;
        seed.u64(p.frame);
        seed.u64(self.generations.len() as u64);
        let g = Generation {
            id: sha256::digest(&seed.0),
            birth: p.frame,
            syn: [None; 2],
            anchor: [None; 2],
            low: [0; 2],
            high: [0; 2],
            fin: [None; 2],
            reset: false,
            midstream: !p.syn() || p.ack(),
            last_time: None,
        };
        self.generations.push(g);
        Ok(self.generations.len() - 1)
    }
    /// All wire-header fields are re-derived at this public boundary, preventing
    /// caller-mutated cached fields from becoming authoritative state.
    pub fn ingest(&mut self, input: &TcpInput, s: &SourceIdentity, c: &Config) -> Result<Decision> {
        c.validate()?;
        if input.raw.len() > 65535
            || input.witnesses.len() > c.max_witnesses
            || self.generations.len() > c.max_generations
        {
            return Err(Error::limit("history_state_input"));
        }
        self.key.encode()?;
        let mut candidate = self.clone();
        let result = candidate.ingest_inner(input, s, c)?;
        *self = candidate;
        Ok(result)
    }
    fn ingest_inner(
        &mut self,
        input: &TcpInput,
        s: &SourceIdentity,
        c: &Config,
    ) -> Result<Decision> {
        c.validate()?;
        let p = TcpInput::decode(&input.encode()?, c)?;
        if p.key != self.key {
            return Err(bad("history_key", "input tuple changed"));
        }
        let before = sha256::digest(&self.encode()?);
        let direction = usize::from(p.direction);
        let mut reasons = Vec::new();
        let mut candidates = Vec::<(usize, i64)>::new();
        if p.syn() && !p.ack() {
            for (i, g) in self.generations.iter().enumerate() {
                if !g.closed() && g.syn[direction] == Some(p.sequence) {
                    candidates.push((i, 0));
                }
            }
            if candidates.is_empty() {
                let simultaneous = self.generations.last().filter(|g| {
                    !g.closed()
                        && !g.midstream
                        && g.syn[direction].is_none()
                        && g.syn[1 - direction].is_some()
                        && g.high == [0, 0]
                });
                if simultaneous.is_some() {
                    candidates.push((self.generations.len() - 1, 0));
                    reasons.push("simultaneous_open_candidate".into());
                } else {
                    let i = self.create(&p, s, c)?;
                    candidates.push((i, 0));
                    reasons.push("observed_syn_generation_boundary".into());
                }
            } else {
                reasons.push("repeated_syn_candidate_not_endpoint_identity".into());
            }
        } else if self.generations.is_empty() {
            let i = self.create(&p, s, c)?;
            candidates.push((i, 0));
            reasons.push("missing_initial_syn".into());
        } else {
            for (i, g) in self.generations.iter().enumerate() {
                if p.syn() {
                    if g.closed() || g.syn[direction].is_some_and(|x| x != p.sequence) {
                        continue;
                    }
                    if let Some(peer) = g.syn[1 - direction] {
                        if !p.ack() || p.acknowledgement != peer.wrapping_add(1) {
                            continue;
                        }
                    }
                }
                if let Some(anchor) = g.anchor[direction] {
                    let mut high = g.high[direction];
                    if !g.closed() {
                        high = high
                            .checked_add(c.sequence_horizon)
                            .ok_or_else(|| Error::limit("sequence_span"))?;
                    }
                    let low = if g.syn[direction].is_some() {
                        0
                    } else {
                        g.low[direction]
                            .checked_sub(c.sequence_horizon)
                            .ok_or_else(|| Error::limit("sequence_span"))?
                    };
                    for at in epoch_candidates(
                        p.data_sequence(),
                        anchor,
                        low,
                        high,
                        c.max_epoch_candidates,
                    )? {
                        candidates.push((i, at));
                    }
                } else if !g.closed() {
                    // A captured reverse-direction SYN constrains SYN-ACK. An ACK
                    // without handshake evidence cannot establish peer identity.
                    candidates.push((i, 0));
                }
            }
            if candidates.is_empty() && p.syn() {
                let i = self.create(&p, s, c)?;
                candidates.push((i, 0));
                reasons.push("syn_ack_without_observed_generation".into());
            }
        }
        let mut selected = if candidates.len() == 1 { Some(0) } else { None };
        let mut assumption = false;
        if candidates.len() > 1
            && c.epoch_policy == EpochPolicy::NearestFrontier
            && candidates.iter().all(|x| x.0 == candidates[0].0)
        {
            let g = &self.generations[candidates[0].0];
            let mut ranked: Vec<_> = candidates
                .iter()
                .enumerate()
                .map(|(j, (_, at))| (i128::from(*at).abs_diff(i128::from(g.high[direction])), j))
                .collect();
            ranked.sort_unstable();
            if ranked.len() == 1 || ranked[0].0 < ranked[1].0 {
                selected = Some(ranked[0].1);
                assumption = true;
                reasons.push("nearest_frontier_epoch_assumption_alternatives_retained".into());
            }
        }
        if candidates.len() > 1 {
            reasons.push("multiple_generation_or_sequence_epoch_candidates".into());
        }
        if candidates.is_empty() {
            reasons.push("outside_observed_generation_hypotheses".into());
        }
        if p.window == 0 {
            reasons.push("zero_advertised_window_no_scale_inference".into());
        }
        if let Some(j) = selected {
            let (i, at) = candidates[j];
            let g = &mut self.generations[i];
            if g.closed() {
                reasons.push("late_packet_after_observed_close".into());
            }
            if p.when
                .zip(g.last_time)
                .is_some_and(|(now, last)| now < last)
            {
                reasons.push("capture_clock_reversal".into());
            }
            if let Some(t) = p.when {
                g.last_time = Some(g.last_time.map_or(t, |old| old.max(t)));
            } else {
                reasons.push("timestamp_unavailable".into());
            }
            if p.syn() {
                g.syn[direction] = Some(p.sequence);
            }
            g.anchor[direction].get_or_insert(p.data_sequence());
            let end = at
                .checked_add(p.payload().len() as i64)
                .ok_or_else(|| Error::limit("sequence_span"))?;
            if let Some(fin) = g.fin[direction] {
                if end > fin && !p.payload().is_empty() {
                    reasons.push("payload_beyond_observed_fin".into());
                }
            }
            g.low[direction] = g.low[direction].min(at);
            g.high[direction] = g.high[direction].max(end);
            if p.fin() {
                if g.fin[direction].is_some_and(|old| old != end) {
                    reasons.push("conflicting_fin_position".into());
                } else {
                    g.fin[direction] = Some(end);
                }
            }
            g.reset |= p.rst();
        }
        let placements = candidates
            .iter()
            .enumerate()
            .map(|(j, (i, at))| Placement {
                generation: self.generations[*i].id,
                direction: p.direction,
                offset: *at,
                selected: selected == Some(j),
            })
            .collect();
        let after = sha256::digest(&self.encode()?);
        Ok(Decision {
            before,
            after,
            placements,
            reasons,
            policy_assumption: assumption,
        })
    }
}
/// Enumerate wire-sequence aliases within a declared relative range. Exact
/// half-space ambiguity is never resolved using wall-clock time or a vote.
pub fn epoch_candidates(
    sequence: u32,
    anchor: u32,
    low: i64,
    high: i64,
    max: usize,
) -> Result<Vec<i64>> {
    if low > high || max == 0 || max > 64 {
        return Err(bad("sequence_epoch", "invalid range/budget"));
    }
    let residue = i128::from(sequence.wrapping_sub(anchor));
    let modulus = i128::from(MODULUS);
    let lo = i128::from(low);
    let hi = i128::from(high);
    let first = (lo - residue + modulus - 1).div_euclid(modulus);
    let last = (hi - residue).div_euclid(modulus);
    if last < first {
        return Ok(Vec::new());
    }
    if last - first + 1 > max as i128 {
        return Err(Error::limit("sequence_epoch_candidates"));
    }
    (first..=last)
        .map(|k| i64::try_from(residue + k * modulus).map_err(|_| Error::limit("sequence_epoch")))
        .collect()
}
struct Cached {
    state: TupleState,
    used: u64,
}
/// Tuple caches are disposable projections. Restart replays the canonical journal;
/// it never trusts an on-disk state cache as its independent authority.
pub struct Store {
    root: PathBuf,
    hot: BTreeMap<[u8; 32], Cached>,
    clock: u64,
    config: Config,
    source: SourceIdentity,
    quota: Quota,
    failed: bool,
}
impl Store {
    pub fn new(root: &Path, config: Config, source: SourceIdentity, quota: Quota) -> Result<Self> {
        config.validate()?;
        fs::create_dir(root)?;
        Ok(Self {
            root: root.to_owned(),
            hot: BTreeMap::new(),
            clock: 0,
            config,
            source,
            quota,
            failed: false,
        })
    }
    fn path(&self, k: &[u8; 32]) -> PathBuf {
        self.root.join(format!("{}.state", sha256::hex(k)))
    }
    fn spill(&mut self, id: [u8; 32]) -> Result<()> {
        let cached = self
            .hot
            .remove(&id)
            .ok_or_else(|| bad("state_cache", "missing entry"))?;
        let bytes = cached.state.encode()?;
        let mut e = Encoder::default();
        e.bytes(&bytes)?;
        e.hash(&sha256::digest(&bytes));
        journal::write_new(&self.path(&id), &e.0, &self.quota)
    }
    pub fn ingest(&mut self, p: &TcpInput) -> Result<Decision> {
        if self.failed {
            return Err(bad(
                "state_cache",
                "failed store; replay into a new workspace",
            ));
        }
        let result = self.ingest_inner(p);
        if result.is_err() {
            self.failed = true;
        }
        result
    }
    fn ingest_inner(&mut self, p: &TcpInput) -> Result<Decision> {
        let id = p.key.digest()?;
        if !self.hot.contains_key(&id) {
            if self.hot.len() >= self.config.hot_tuples {
                let oldest = self
                    .hot
                    .iter()
                    .min_by_key(|(_, v)| v.used)
                    .map(|(k, _)| *k)
                    .ok_or_else(|| bad("state_cache", "empty eviction"))?;
                self.spill(oldest)?;
            }
            let path = self.path(&id);
            let state = if path.try_exists()? {
                journal::regular(&path)?;
                let maximum = 10064usize
                    .checked_add(self.config.max_generations * 256)
                    .ok_or_else(|| Error::limit("history_state"))?;
                if fs::metadata(&path)?.len() > maximum as u64 {
                    return Err(Error::limit("history_state"));
                }
                let bytes = fs::read(&path)?;
                let mut d = Decoder::new(&bytes);
                let body = d.bytes(maximum)?;
                let hash = d.hash()?;
                d.finish()?;
                if sha256::digest(body) != hash {
                    return Err(bad("history_state", "cache checksum mismatch"));
                }
                let s = TupleState::decode(body, &self.config)?;
                if s.key != p.key {
                    return Err(bad("history_state", "cache key mismatch"));
                }
                journal::remove_owned(&path, &self.quota)?;
                s
            } else {
                TupleState::new(p.key.clone())
            };
            self.hot.insert(id, Cached { state, used: 0 });
        }
        self.clock = self
            .clock
            .checked_add(1)
            .ok_or_else(|| Error::limit("state_clock"))?;
        let cached = self
            .hot
            .get_mut(&id)
            .ok_or_else(|| bad("state_cache", "entry disappeared"))?;
        cached.used = self.clock;
        cached.state.ingest(p, &self.source, &self.config)
    }
    pub fn finish(mut self) -> Result<()> {
        if self.failed {
            return Err(bad("state_cache", "failed store"));
        }
        while let Some(id) = self.hot.keys().next().copied() {
            self.spill(id)?;
        }
        Ok(())
    }
}
