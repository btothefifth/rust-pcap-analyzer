//! Source-ordered evidence visitor over verified PCBMRT02 records. This path
//! retains one record, its actual active PIT, and capped BGP4MP session grammar.
//! It never accumulates observations or derived RIB history.
use super::{
    bgp,
    bgp_mrt::{Bgp4mpPayload, MrtBatch, MrtBody, MrtRecord, MrtTime, SCHEMA},
    bgp_mrt_store::MrtReplayOptions,
    bgp_mrt_stream_store::{self as store, MrtStreamLimits, StreamReceipt},
    model::Limits,
};
use pcap_evidence::{json::Json, sha256, Error, ErrorCode, Result};
use std::{
    fs::File,
    io::{Read, Seek, SeekFrom},
    path::Path,
};

/// Borrowed evidence from one exact source record. A callback must treat every
/// row as provisional until visit_verified returns its final matching receipt.
/// On any error discard the provisional sink, including already-written rows.
pub struct StreamEvent<'a> {
    pub receipt: &'a StreamReceipt,
    /// Zero-based source ordinal, independent of storage or I/O chunk boundaries.
    pub record_ordinal: u64,
    pub record_offset: u64,
    pub record_bytes: u64,
    /// Exact common-header discriminator; ET with absent/invalid microseconds
    /// must remain distinguishable from ordinary seconds-only records.
    pub record_type: u16,
    pub subtype: u16,
    pub record_sha256: &'a str,
    pub time: MrtTime,
    pub entry_index: Option<usize>,
    pub originated_seconds: Option<u32>,
    pub event: &'a Json,
    pub observation: Option<&'a Json>,
}
fn record_event(record: &MrtRecord, kind: &str) -> Json {
    let reason = match &record.body {
        MrtBody::Opaque { reason, .. } => Some(*reason),
        _ => None,
    };
    Json::object([
        ("schema", "pcap-evidence.bgp.mrt-stream-event.v2".into()),
        ("kind", kind.into()),
        ("record_type", record.record_type.into()),
        ("subtype", record.subtype.into()),
        ("reason", reason.map_or(Json::Null, Json::from)),
        ("source_authenticated", false.into()),
        ("endpoint_state_claimed", false.into()),
    ])
}
struct VisitorBudget {
    work: u64,
    output: u64,
    high: usize,
    retained_base: usize,
    retained_cap: usize,
}
impl VisitorBudget {
    #[allow(clippy::too_many_arguments)]
    fn emit<F: FnMut(StreamEvent<'_>) -> Result<()>>(
        &mut self,
        receipt: &StreamReceipt,
        ordinal: u64,
        record: &MrtRecord,
        entry: Option<usize>,
        event: &Json,
        observation: Option<&Json>,
        l: &MrtStreamLimits,
        visitor: &mut F,
        state: &bgp::mrt::ReplayState,
        deep: &Limits,
    ) -> Result<()> {
        let session_bytes = state.retained_bytes(deep)?;
        let retained = self
            .retained_base
            .checked_add(session_bytes)
            .and_then(|n| n.checked_add(store::json_memory(event)))
            .and_then(|n| n.checked_add(observation.map_or(0, store::json_memory)))
            .filter(|n| *n <= self.retained_cap)
            .ok_or_else(|| Error::limit("mrt_stream_retained"))?;
        self.high = self.high.max(retained);
        store::charge(
            &mut self.work,
            (session_bytes as u64)
                .checked_mul(8)
                .ok_or_else(|| Error::limit("mrt_stream_work"))?,
            l.work,
            "mrt_stream_work",
        )?;
        let remaining = l.output_bytes.saturating_sub(self.output);
        let cap = usize::try_from(remaining).unwrap_or(usize::MAX);
        let mut size = event.encoded_len_bounded(cap)? as u64;
        if let Some(observation) = observation {
            size = size
                .checked_add(observation.encoded_len_bounded(cap)? as u64)
                .ok_or_else(|| Error::limit("mrt_stream_output"))?;
        }
        store::charge(&mut self.output, size, l.output_bytes, "mrt_stream_output")?;
        store::charge(
            &mut self.work,
            size.checked_mul(16)
                .ok_or_else(|| Error::limit("mrt_stream_work"))?,
            l.work,
            "mrt_stream_work",
        )?;
        let originated_seconds = entry.and_then(|index| match &record.body {
            MrtBody::Rib(r) => r.entries.get(index).map(|e| e.originated_seconds),
            _ => None,
        });
        visitor(StreamEvent {
            receipt,
            record_ordinal: ordinal,
            record_offset: record.offset,
            record_bytes: u64::from(record.length) + 12,
            record_type: record.record_type,
            subtype: record.subtype,
            record_sha256: &record.sha256,
            time: record.time,
            entry_index: entry,
            originated_seconds,
            event,
            observation,
        })
    }
}

/// Complete semantic container verification precedes the first callback.
/// Replay then performs a second full verification and compares terminal source
/// identity again. Callback effects are caller-owned provisional output until
/// this returns success. Concurrent mutation may invalidate the second pass.
pub fn visit_verified<R: Read + Seek, F: FnMut(StreamEvent<'_>) -> Result<()>>(
    reader: &mut R,
    limits: &MrtStreamLimits,
    deep_limits: &Limits,
    options: &MrtReplayOptions,
    mut visitor: F,
) -> Result<StreamReceipt> {
    limits.validate()?;
    deep_limits.validate()?;
    let verified = store::verify_stream(reader, limits)?;
    let mut effective = deep_limits.clone();
    effective.active = effective.active.min(limits.sessions);
    let mut budget = VisitorBudget {
        work: 0,
        output: 0,
        high: verified.high_water_bytes,
        retained_base: 0,
        retained_cap: deep_limits.retained_bytes,
    };
    // Reserve both complete verification scans before emitting any rows.
    store::charge(
        &mut budget.work,
        verified
            .work_used
            .checked_mul(2)
            .ok_or_else(|| Error::limit("mrt_stream_work"))?,
        limits.work,
        "mrt_stream_work",
    )?;
    let mut state = bgp::mrt::ReplayState::with_peer_relationship(options.peer_relationship);
    let mut pit: Option<MrtRecord> = None;
    reader.seek(SeekFrom::Start(0)).map_err(Error::io)?;
    let second = store::scan(reader, limits, |ordinal, _offset, raw, record| {
        let index =
            usize::try_from(ordinal).map_err(|_| Error::limit("mrt_stream_record_ordinal"))?;
        store::charge(
            &mut budget.work,
            (raw.len() as u64)
                .checked_mul(64)
                .ok_or_else(|| Error::limit("mrt_stream_work"))?,
            limits.work,
            "mrt_stream_work",
        )?;
        if record.record_type != 13 || !matches!(record.subtype,1..=6|8..=12) {
            pit = None;
        }
        if matches!(record.body, MrtBody::PeerIndex(_)) {
            pit = None;
        }
        let pit_memory = pit.as_ref().map_or(0, store::record_memory);
        let record_memory = store::record_memory(&record);
        let mut records = Vec::with_capacity(2);
        if let Some(old) = pit.take() {
            records.push(old);
        }
        let record_index = records.len();
        records.push(record);
        let mut batch = MrtBatch {
            schema: SCHEMA,
            source: verified.source.clone(),
            sha256: verified.sha256.clone(),
            byte_length: verified.byte_length,
            source_authenticated: false,
            records,
            retained_bytes: 0,
            work_charge: 0,
            output_charge: 0,
        };
        budget.retained_base = raw
            .len()
            .checked_add(pit_memory)
            .and_then(|n| n.checked_add(record_memory))
            .and_then(|n| {
                n.checked_add(batch.records.capacity() * std::mem::size_of::<MrtRecord>())
            })
            .and_then(|n| {
                n.checked_add(
                    batch.source.source_id.capacity()
                        + batch.source.checkpoint_id.capacity()
                        + batch.sha256.capacity(),
                )
            })
            .filter(|n| *n < deep_limits.retained_bytes)
            .ok_or_else(|| Error::limit("mrt_stream_retained"))?;
        effective.retained_bytes = deep_limits.retained_bytes - budget.retained_base;
        let record = &batch.records[record_index];
        match &record.body {
            MrtBody::Rib(rib) if !rib.entries.is_empty() => {
                for entry in 0..rib.entries.len() {
                    let observation = batch.normalize_rib_entry(record_index, entry, &effective)?;
                    let event = record_event(
                        record,
                        if observation.is_some() {
                            "rib_entry"
                        } else {
                            "unsupported_rib_entry"
                        },
                    );
                    budget.emit(
                        &verified,
                        ordinal,
                        record,
                        Some(entry),
                        &event,
                        observation.as_ref(),
                        limits,
                        &mut visitor,
                        &state,
                        &effective,
                    )?;
                }
            }
            MrtBody::Bgp4mp(b) => match &b.payload {
                Bgp4mpPayload::Message(embedded) => {
                    let range = batch
                        .bgp4mp_message_source_range(record_index)?
                        .ok_or_else(|| {
                            Error::new(
                                ErrorCode::Invariant,
                                record.offset,
                                "mrt_stream_message_range",
                                "message range absent",
                            )
                        })?;
                    let start = usize::try_from(range.start - record.offset)
                        .map_err(|_| Error::limit("mrt_stream_message_range"))?;
                    let end = usize::try_from(range.end - record.offset)
                        .map_err(|_| Error::limit("mrt_stream_message_range"))?;
                    let original = raw
                        .get(start..end)
                        .ok_or_else(|| Error::limit("mrt_stream_message_range"))?;
                    if original != embedded.as_slice()
                        || range.sha256.as_deref()
                            != Some(sha256::hex(&sha256::digest(original)).as_str())
                    {
                        return Err(Error::new(
                            ErrorCode::SourceMismatch,
                            record.offset,
                            "mrt_stream_message_range",
                            "message differs from original source",
                        ));
                    }
                    let replay = bgp::mrt::replay_message_record(
                        &batch, index, record, range, &effective, &mut state,
                    )?;
                    budget.emit(
                        &verified,
                        ordinal,
                        record,
                        None,
                        &replay.event,
                        replay.observation.as_ref(),
                        limits,
                        &mut visitor,
                        &state,
                        &effective,
                    )?;
                }
                Bgp4mpPayload::State { .. } => {
                    let event = bgp::mrt::replay_state_record(
                        &batch, index, record, &effective, &mut state,
                    )?;
                    budget.emit(
                        &verified,
                        ordinal,
                        record,
                        None,
                        &event,
                        None,
                        limits,
                        &mut visitor,
                        &state,
                        &effective,
                    )?;
                }
            },
            MrtBody::Opaque {
                reason: "malformed_bgp4mp_record",
                ..
            } => {
                let event = bgp::mrt::replay_malformed_record(
                    &batch, index, record, &effective, &mut state,
                )?;
                budget.emit(
                    &verified,
                    ordinal,
                    record,
                    None,
                    &event,
                    None,
                    limits,
                    &mut visitor,
                    &state,
                    &effective,
                )?;
            }
            _ => {
                let kind = match &record.body {
                    MrtBody::PeerIndex(_) => "peer_index",
                    MrtBody::Rib(_) => "empty_rib",
                    _ => "opaque_record",
                };
                let event = record_event(record, kind);
                budget.emit(
                    &verified,
                    ordinal,
                    record,
                    None,
                    &event,
                    None,
                    limits,
                    &mut visitor,
                    &state,
                    &effective,
                )?;
            }
        }
        if matches!(batch.records[record_index].body, MrtBody::PeerIndex(_)) {
            pit = batch.records.pop();
        } else if record_index == 1 {
            batch.records.pop();
            pit = batch.records.pop();
        }
        Ok(())
    })?;
    if !verified.same_identity(&second) {
        return Err(Error::new(
            ErrorCode::SourceMismatch,
            0,
            "mrt_stream_changed",
            "source store changed between verification passes",
        ));
    }
    let mut receipt = second;
    receipt.high_water_bytes = receipt.high_water_bytes.max(budget.high);
    receipt.work_used = budget.work;
    receipt.output_bytes = budget.output;
    Ok(receipt)
}
pub fn visit_verified_path<F: FnMut(StreamEvent<'_>) -> Result<()>>(
    path: &Path,
    limits: &MrtStreamLimits,
    deep_limits: &Limits,
    options: &MrtReplayOptions,
    visitor: F,
) -> Result<StreamReceipt> {
    visit_verified(
        &mut File::open(path).map_err(Error::io)?,
        limits,
        deep_limits,
        options,
        visitor,
    )
}
