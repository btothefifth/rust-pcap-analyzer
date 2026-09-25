//! Source-neutral BGP4MP message locators. No packet IDs, synthetic capture
//! evidence, inferred negotiated capabilities, or endpoint authority are added.
use super::*;

impl MrtBatch {
    /// Locate the exact embedded BGP frame in the original MRT byte domain.
    /// The returned range is interpreted within this batch's source/checkpoint
    /// and batch hash. Its digest covers the message bytes, not the whole record.
    ///
    /// This validates structural consistency, not authenticity or a mutation
    /// of these public structs against an external file. A persisted consumer
    /// must verify/reparse the original source before using any derived range.
    pub fn bgp4mp_message_source_range(&self, record_index: usize) -> Result<Option<SourceRange>> {
        let record = self
            .records
            .get(record_index)
            .ok_or_else(|| bad("mrt_record_index", 0, "missing record"))?;
        let MrtBody::Bgp4mp(message) = &record.body else {
            return Ok(None);
        };
        let Bgp4mpPayload::Message(bytes) = &message.payload else {
            return Ok(None);
        };
        let (width, local, add_path) = match record.subtype {
            1 => (2u8, false, false),
            4 => (4, false, false),
            6 => (2, true, false),
            7 => (4, true, false),
            8 => (2, false, true),
            9 => (4, false, true),
            10 => (2, true, true),
            11 => (4, true, true),
            _ => return Err(bad("mrt_message_range", 0, "not a message subtype")),
        };
        if !matches!(record.record_type, 16 | 17)
            || (record.record_type == 17) != record.time.microseconds.is_some()
            || message.asn_width != width
            || message.asn_width_source != AsnWidthSource::Bgp4mpSubtype
            || message.locally_generated != local
            || message.add_path != add_path
            || (width == 2
                && (message.peer_asn > u32::from(u16::MAX)
                    || message.local_asn > u32::from(u16::MAX)))
        {
            return Err(bad(
                "mrt_message_range",
                0,
                "container layout metadata disagrees",
            ));
        }
        let address_bytes = match (
            message.address_afi,
            message.peer_address,
            message.local_address,
        ) {
            (1, IpAddr::V4(_), IpAddr::V4(_)) => 4u64,
            (2, IpAddr::V6(_), IpAddr::V6(_)) => 16u64,
            _ => {
                return Err(bad(
                    "mrt_message_range",
                    0,
                    "address family metadata disagrees",
                ))
            }
        };
        if bytes.len() < 19
            || bytes[..16] != [0xff; 16]
            || usize::from(u16::from_be_bytes([bytes[16], bytes[17]])) != bytes.len()
        {
            return Err(bad(
                "mrt_message_range",
                0,
                "embedded frame boundary disagrees",
            ));
        }
        let extended_time = if record.record_type == 17 { 4u64 } else { 0 };
        let preamble = extended_time + u64::from(width) * 2 + 4 + address_bytes * 2;
        let message_length =
            u64::try_from(bytes.len()).map_err(|_| Error::limit("mrt_message_range"))?;
        if preamble.checked_add(message_length) != Some(u64::from(record.length)) {
            return Err(bad(
                "mrt_message_range",
                0,
                "record length does not match message range",
            ));
        }
        let start = record
            .offset
            .checked_add(12)
            .and_then(|value| value.checked_add(preamble))
            .ok_or_else(|| Error::limit("mrt_message_range"))?;
        let end = start
            .checked_add(message_length)
            .filter(|value| *value <= self.byte_length)
            .ok_or_else(|| Error::limit("mrt_message_range"))?;
        Ok(Some(SourceRange {
            start,
            end,
            sha256: Some(sha256::hex(&sha256::digest(bytes))),
        }))
    }
    /// Verify the batch digest, enclosing record digest/header, and located
    /// message bytes against an original MRT slice. Work is O(source length)
    /// per call, capped at the adapter's 64 MiB input ceiling. This establishes
    /// range/byte consistency, not collector authenticity or the correctness
    /// of unrelated fields in caller-mutated public structs.
    pub fn verified_bgp4mp_message_source_range(
        &self,
        record_index: usize,
        source: &[u8],
    ) -> Result<Option<SourceRange>> {
        if source.len() > 64 * 1024 * 1024
            || u64::try_from(source.len()).ok() != Some(self.byte_length)
        {
            return Err(Error::limit("mrt_message_source"));
        }
        if sha256::hex(&sha256::digest(source)) != self.sha256 {
            return Err(bad(
                "mrt_message_source",
                0,
                "batch digest disagrees with original bytes",
            ));
        }
        let record = self
            .records
            .get(record_index)
            .ok_or_else(|| bad("mrt_record_index", 0, "missing record"))?;
        let record_start =
            usize::try_from(record.offset).map_err(|_| Error::limit("mrt_message_source"))?;
        let header_end = record_start
            .checked_add(12)
            .ok_or_else(|| Error::limit("mrt_message_source"))?;
        let original_header = source.get(record_start..header_end).ok_or_else(|| {
            bad(
                "mrt_message_source",
                record_start,
                "record header is outside original source",
            )
        })?;
        if original_header[..4] != record.time.seconds.to_be_bytes()
            || original_header[4..6] != record.record_type.to_be_bytes()
            || original_header[6..8] != record.subtype.to_be_bytes()
            || original_header[8..12] != record.length.to_be_bytes()
        {
            return Err(bad(
                "mrt_message_source",
                record_start,
                "record header differs from original source",
            ));
        }
        let header_identifies_message = matches!(record.record_type, 16 | 17)
            && matches!(record.subtype, 1 | 4 | 6 | 7 | 8 | 9 | 10 | 11);
        let Some(range) = self.bgp4mp_message_source_range(record_index)? else {
            if header_identifies_message {
                return Err(bad(
                    "mrt_message_source",
                    record_start,
                    "source identifies a BGP4MP message but its parsed payload is absent",
                ));
            }
            return Ok(None);
        };
        let start = usize::try_from(range.start).map_err(|_| Error::limit("mrt_message_source"))?;
        let end = usize::try_from(range.end).map_err(|_| Error::limit("mrt_message_source"))?;
        let original_record = source.get(record_start..end).ok_or_else(|| {
            bad(
                "mrt_message_source",
                record_start,
                "record is outside original source",
            )
        })?;
        if original_record.len() < 12
            || original_record[..4] != record.time.seconds.to_be_bytes()
            || original_record[4..6] != record.record_type.to_be_bytes()
            || original_record[6..8] != record.subtype.to_be_bytes()
            || original_record[8..12] != record.length.to_be_bytes()
            || sha256::hex(&sha256::digest(original_record)) != record.sha256
        {
            return Err(bad(
                "mrt_message_source",
                record_start,
                "enclosing record binding disagrees",
            ));
        }
        if let Some(microseconds) = record.time.microseconds {
            if original_record.get(12..16) != Some(microseconds.to_be_bytes().as_slice()) {
                return Err(bad(
                    "mrt_message_source",
                    record_start,
                    "extended timestamp binding disagrees",
                ));
            }
        }
        let MrtBody::Bgp4mp(message) = &record.body else {
            return Err(bad(
                "mrt_message_source",
                record_start,
                "message record disappeared",
            ));
        };
        let Bgp4mpPayload::Message(bytes) = &message.payload else {
            return Err(bad(
                "mrt_message_source",
                record_start,
                "message payload disappeared",
            ));
        };
        if source.get(start..end) != Some(bytes.as_slice()) {
            return Err(bad(
                "mrt_message_source",
                start,
                "located message differs from original bytes",
            ));
        }
        Ok(Some(range))
    }
}

#[cfg(test)]
mod index_tests {
    use super::*;

    fn record(kind: u16, subtype: u16, body: &[u8]) -> Vec<u8> {
        let mut bytes = 11u32.to_be_bytes().to_vec();
        bytes.extend_from_slice(&kind.to_be_bytes());
        bytes.extend_from_slice(&subtype.to_be_bytes());
        bytes.extend_from_slice(&(body.len() as u32).to_be_bytes());
        bytes.extend_from_slice(body);
        bytes
    }

    fn batch() -> MrtBatch {
        let mut peer = vec![192, 0, 2, 1, 0, 0, 0, 1, 2, 192, 0, 2, 2, 203, 0, 113, 9];
        peer.extend_from_slice(&65551u32.to_be_bytes());
        let table = record(13, 1, &peer);
        let mut attributes = vec![0x40, 1, 1, 0, 0x40, 2, 6, 2, 1];
        attributes.extend_from_slice(&65551u32.to_be_bytes());
        attributes.extend_from_slice(&[0x40, 3, 4, 192, 0, 2, 9]);
        let mut rib = vec![0, 0, 0, 1, 24, 203, 0, 113, 0, 1, 0, 0];
        rib.extend_from_slice(&10u32.to_be_bytes());
        rib.extend_from_slice(&(attributes.len() as u16).to_be_bytes());
        rib.extend_from_slice(&attributes);
        let rib = record(13, 2, &rib);
        MrtBatch::parse(
            &[table.clone(), rib.clone(), table, rib].concat(),
            MrtSource {
                source_id: "collector".into(),
                checkpoint_id: "snapshot".into(),
            },
            &MrtLimits::default(),
        )
        .unwrap()
    }

    #[test]
    fn offset_lookup_finds_source_records_without_linear_scan() {
        let batch = batch();
        for (index, record) in batch.records.iter().enumerate() {
            let (found, probes) = batch.record_index_by_offset(record.offset).unwrap();
            assert_eq!(found, index);
            assert!(probes <= 4);
        }
    }

    #[test]
    fn missing_offsets_records_and_entries_are_rejected() {
        let batch = batch();
        let limits = super::super::super::model::Limits::default();
        assert!(batch.record_index_by_offset(1).is_none());
        assert!(batch.record_index_by_offset(u64::MAX).is_none());
        assert!(batch.normalize_rib_entry(usize::MAX, 0, &limits).is_err());
        assert!(batch.normalize_rib_entry(1, usize::MAX, &limits).is_err());
    }

    #[test]
    fn normalization_rechecks_digest_type_and_peer_index() {
        let original = batch();
        let limits = super::super::super::model::Limits::default();
        let mut changed = original.clone();
        changed.records[2].sha256 = "00".repeat(32);
        assert!(changed.normalize_rib_entry(3, 0, &limits).is_err());
        let mut changed = original.clone();
        changed.records[2].body = MrtBody::Opaque {
            reason: "fixture",
            bytes: vec![],
        };
        assert!(changed.normalize_rib_entry(3, 0, &limits).is_err());
        let mut changed = original;
        let MrtBody::Rib(rib) = &mut changed.records[3].body else {
            panic!("RIB");
        };
        rib.entries[0].peer_index = 99;
        assert!(changed.normalize_rib_entry(3, 0, &limits).is_err());
    }
}
