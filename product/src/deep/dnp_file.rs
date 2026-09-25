//! Conservative Group 70 file-transfer evidence reconciliation.
//!
//! This module correlates already verified, complete DNP3 application messages.
//! It never reconstructs a file path, authenticates a peer, or claims that an
//! endpoint accepted, wrote, closed, or executed a file. Missing, duplicate,
//! and conflicting blocks remain visible in the candidate projection.
use super::model::Limits;
use pcap_evidence::{json::Json, provenance::EvidenceBytes, sha256, Error, Result};
use std::collections::{BTreeMap, BTreeSet};

fn truncated(field: &'static str, offset: usize) -> Error {
    Error::new(
        pcap_evidence::ErrorCode::Truncated,
        offset as u64,
        field,
        "file object ended before the required field",
    )
}
fn unsupported(field: &'static str) -> Error {
    Error::new(
        pcap_evidence::ErrorCode::UnsupportedTransport,
        0,
        field,
        "file object variation is outside the reconciliation subset",
    )
}

#[derive(Clone, Debug)]
struct Descriptor {
    file_size: u64,
    maximum_block_size: u64,
}

#[derive(Clone, Debug)]
struct Block {
    length: usize,
    sha256: String,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct Scope {
    session: u64,
    low: u16,
    high: u16,
}

#[derive(Clone, Debug)]
struct State {
    scope: Scope,
    handle: u32,
    last_function: u8,
    request_ids: BTreeSet<u16>,
    variations: BTreeSet<u8>,
    directions: BTreeSet<u8>,
    blocks: BTreeMap<u32, Block>,
    duplicate_blocks: BTreeSet<u32>,
    conflicting_blocks: BTreeSet<u32>,
    status_without_content_blocks: BTreeSet<u32>,
    metadata_conflict: bool,
    status_codes: BTreeSet<u8>,
    declared: Option<Descriptor>,
    witnesses: Vec<Json>,
}

#[derive(Clone, Debug)]
enum FileObject {
    Descriptor {
        variation: u8,
        request_id: u16,
        file_size: u64,
        maximum_block_size: u64,
    },
    Status {
        variation: u8,
        handle: u32,
        request_id: u16,
        file_size: u64,
        maximum_block_size: u64,
        status: u8,
    },
    Block {
        variation: u8,
        handle: u32,
        block: u32,
        length: usize,
        sha256: String,
    },
    BlockStatus {
        variation: u8,
        handle: u32,
        block: u32,
        status: u8,
    },
    Specification {
        variation: u8,
    },
    Authentication,
}

#[derive(Clone, Debug)]
enum Parsed {
    None,
    Objects(Vec<FileObject>),
    Unsupported(&'static str),
    Incomplete(&'static str),
}

fn le16(b: &[u8], at: usize) -> Result<u16> {
    let v = b
        .get(at..at + 2)
        .ok_or_else(|| truncated("dnp_file_field", at))?;
    Ok(u16::from_le_bytes([v[0], v[1]]))
}

fn le32(b: &[u8], at: usize) -> Result<u32> {
    let v = b
        .get(at..at + 4)
        .ok_or_else(|| truncated("dnp_file_field", at))?;
    Ok(u32::from_le_bytes([v[0], v[1], v[2], v[3]]))
}

fn parse_object(variation: u8, b: &[u8]) -> Result<FileObject> {
    match variation {
        2 => Ok(FileObject::Authentication),
        3 => {
            if b.len() < 26 {
                return Err(truncated("dnp_file_command", b.len()));
            }
            let name_offset = usize::from(le16(b, 0)?);
            let name_length = usize::from(le16(b, 2)?);
            if name_offset != 26
                || name_offset
                    .checked_add(name_length)
                    .is_none_or(|end| end != b.len())
            {
                return Err(Error::new(
                    pcap_evidence::ErrorCode::InvalidLength,
                    0,
                    "dnp_file_name_range",
                    "descriptor filename range is not exact",
                ));
            }
            Ok(FileObject::Descriptor {
                variation,
                request_id: le16(b, 24)?,
                file_size: u64::from(le32(b, 16)?),
                maximum_block_size: u64::from(le16(b, 22)?),
            })
        }
        4 => {
            if b.len() < 13 {
                return Err(truncated("dnp_file_status", b.len()));
            }
            Ok(FileObject::Status {
                variation,
                handle: le32(b, 0)?,
                file_size: u64::from(le32(b, 4)?),
                maximum_block_size: u64::from(le16(b, 8)?),
                request_id: le16(b, 10)?,
                status: b[12],
            })
        }
        5 => {
            if b.len() < 8 {
                return Err(truncated("dnp_file_transport", b.len()));
            }
            Ok(FileObject::Block {
                variation,
                handle: le32(b, 0)?,
                block: le32(b, 4)?,
                length: b.len() - 8,
                sha256: sha256::hex(&sha256::digest(&b[8..])),
            })
        }
        6 => {
            if b.len() < 9 {
                return Err(truncated("dnp_file_transport_status", b.len()));
            }
            Ok(FileObject::BlockStatus {
                variation,
                handle: le32(b, 0)?,
                block: le32(b, 4)?,
                status: b[8],
            })
        }
        7 => {
            if b.len() < 20 {
                return Err(truncated("dnp_file_descriptor", b.len()));
            }
            let name_offset = usize::from(le16(b, 0)?);
            let name_length = usize::from(le16(b, 2)?);
            if name_offset != 20
                || name_offset
                    .checked_add(name_length)
                    .is_none_or(|end| end != b.len())
            {
                return Err(Error::new(
                    pcap_evidence::ErrorCode::InvalidLength,
                    0,
                    "dnp_file_name_range",
                    "descriptor filename range is not exact",
                ));
            }
            Ok(FileObject::Descriptor {
                variation,
                request_id: le16(b, 18)?,
                file_size: u64::from(le32(b, 6)?),
                maximum_block_size: 0,
            })
        }
        8 => Ok(FileObject::Specification { variation }),
        _ => Err(unsupported("dnp_file_variation")),
    }
}

fn parse(bytes: &EvidenceBytes, limits: &Limits) -> Result<Parsed> {
    let b = bytes.data();
    if b.is_empty() {
        return Ok(Parsed::None);
    }
    if b.len() < 4 {
        return Ok(Parsed::Incomplete("file_object_header_truncated"));
    }
    let mut p = 0;
    let mut objects = Vec::new();
    while p < b.len() {
        if b.len() - p < 4 {
            return Ok(Parsed::Incomplete("file_object_header_truncated"));
        }
        let group = b[p];
        let variation = b[p + 1];
        let qualifier = b[p + 2];
        if group != 70 || qualifier != 0x5b {
            return if objects.is_empty() {
                Ok(Parsed::None)
            } else {
                Ok(Parsed::Unsupported("mixed_file_and_non_file_objects"))
            };
        }
        let count = usize::from(b[p + 3]);
        if count > limits.elements.saturating_sub(objects.len()) {
            return Err(Error::limit("dnp_file_objects"));
        }
        p += 4;
        for _ in 0..count {
            if b.len() - p < 2 {
                return Ok(Parsed::Incomplete("file_object_length_truncated"));
            }
            let length = usize::from(le16(b, p)?);
            p += 2;
            let end = p
                .checked_add(length)
                .ok_or_else(|| Error::limit("dnp_file_object"))?;
            if end > b.len() {
                return Ok(Parsed::Incomplete("file_object_truncated"));
            }
            objects.push(parse_object(variation, &b[p..end])?);
            p = end;
        }
    }
    Ok(Parsed::Objects(objects))
}

pub struct FileReconciler {
    pending: BTreeMap<(Scope, u16), Descriptor>,
    states: BTreeMap<(Scope, u32), State>,
}

pub struct Observation<'a> {
    pub session: u64,
    pub direction: u8,
    pub source: u16,
    pub destination: u16,
    pub function: u8,
    pub objects: &'a EvidenceBytes,
    pub evidence: Json,
}

impl Default for FileReconciler {
    fn default() -> Self {
        Self::new()
    }
}

impl FileReconciler {
    pub fn new() -> Self {
        Self {
            pending: BTreeMap::new(),
            states: BTreeMap::new(),
        }
    }

    pub fn reset(&mut self) {
        self.pending.clear();
        self.states.clear();
    }

    pub fn reset_session(&mut self, session: u64) {
        self.pending
            .retain(|(scope, _), _| scope.session != session);
        self.states.retain(|(scope, _), _| scope.session != session);
    }

    pub fn observe(
        &mut self,
        observation: Observation<'_>,
        limits: &Limits,
    ) -> Result<Option<Json>> {
        let parsed = parse(observation.objects, limits)?;
        let file_objects = match parsed {
            Parsed::None => return Ok(None),
            Parsed::Objects(objects) => objects,
            Parsed::Unsupported(reason) => {
                return Ok(Some(Json::object([
                    ("schema", "pcap-evidence.dnp3-file-reconciliation.v1".into()),
                    ("status", "unsupported".into()),
                    ("reason", reason.into()),
                    ("device_effect_established", false.into()),
                ])))
            }
            Parsed::Incomplete(reason) => {
                return Ok(Some(Json::object([
                    ("schema", "pcap-evidence.dnp3-file-reconciliation.v1".into()),
                    ("status", "incomplete".into()),
                    ("reason", reason.into()),
                    ("device_effect_established", false.into()),
                ])))
            }
        };
        if file_objects.is_empty() {
            return Ok(None);
        }
        let scope = Scope {
            session: observation.session,
            low: observation.source.min(observation.destination),
            high: observation.source.max(observation.destination),
        };
        let mut touched = BTreeSet::new();
        for object in file_objects {
            match object {
                FileObject::Authentication => {
                    return Ok(Some(Json::object([
                        ("schema", "pcap-evidence.dnp3-file-reconciliation.v1".into()),
                        ("status", "unsupported".into()),
                        (
                            "reason",
                            "file_authentication_credentials_not_reconciled".into(),
                        ),
                        ("device_effect_established", false.into()),
                    ])))
                }
                FileObject::Specification { variation } => {
                    let _ = variation;
                }
                FileObject::Descriptor {
                    variation,
                    request_id,
                    file_size,
                    maximum_block_size,
                } => {
                    let descriptor = Descriptor {
                        file_size,
                        maximum_block_size,
                    };
                    if self.pending.len() >= limits.active
                        && !self.pending.contains_key(&(scope.clone(), request_id))
                    {
                        return Err(Error::limit("dnp_file_descriptors"));
                    }
                    self.pending
                        .insert((scope.clone(), request_id), descriptor.clone());
                    if maximum_block_size > 0 || file_size == 0 {
                        // Variation 7 has no block-size field; retaining the
                        // descriptor is still useful, but it cannot establish
                        // expected block coverage by itself.
                        let _ = variation;
                    }
                }
                FileObject::Status {
                    variation,
                    handle,
                    request_id,
                    file_size,
                    maximum_block_size,
                    status,
                } => {
                    let key = (scope.clone(), handle);
                    let pending = self.pending.remove(&(scope.clone(), request_id));
                    let state = self.state(key.clone(), observation.function, limits)?;
                    state.request_ids.insert(request_id);
                    state.variations.insert(variation);
                    state.directions.insert(observation.direction);
                    state.status_codes.insert(status);
                    if state.declared.as_ref().is_some_and(|declared| {
                        declared.file_size != file_size
                            || (declared.maximum_block_size > 0
                                && maximum_block_size > 0
                                && declared.maximum_block_size != maximum_block_size)
                    }) {
                        state.metadata_conflict = true;
                    }
                    state.declared = Some(Descriptor {
                        file_size,
                        maximum_block_size,
                    });
                    if let Some(pending) = pending {
                        if pending.file_size != file_size
                            || (pending.maximum_block_size > 0
                                && maximum_block_size > 0
                                && pending.maximum_block_size != maximum_block_size)
                        {
                            state.metadata_conflict = true;
                        }
                    }
                    touched.insert(key);
                }
                FileObject::Block {
                    variation,
                    handle,
                    block,
                    length,
                    sha256,
                } => {
                    let key = (scope.clone(), handle);
                    let state = self.state(key.clone(), observation.function, limits)?;
                    state.variations.insert(variation);
                    state.directions.insert(observation.direction);
                    match state.blocks.get(&block) {
                        Some(old) if old.length == length && old.sha256 == sha256 => {
                            state.duplicate_blocks.insert(block);
                        }
                        Some(_) => {
                            state.conflicting_blocks.insert(block);
                        }
                        None => {
                            state.blocks.insert(block, Block { length, sha256 });
                        }
                    }
                    touched.insert(key);
                }
                FileObject::BlockStatus {
                    variation,
                    handle,
                    block,
                    status,
                } => {
                    let key = (scope.clone(), handle);
                    let state = self.state(key.clone(), observation.function, limits)?;
                    state.variations.insert(variation);
                    state.directions.insert(observation.direction);
                    state.status_codes.insert(status);
                    if !state.blocks.contains_key(&block) {
                        // A status without the corresponding content remains
                        // explicit; it does not authorize inventing content.
                        state.status_without_content_blocks.insert(block);
                    }
                    touched.insert(key);
                }
            }
        }
        for key in &touched {
            let state = self.states.get_mut(key).expect("touched state exists");
            if state.witnesses.len() >= limits.elements {
                return Err(Error::limit("dnp_file_witnesses"));
            }
            state.witnesses.push(observation.evidence.clone());
            state.last_function = observation.function;
        }
        if touched.len() > 1 {
            return Ok(Some(Json::object([
                ("schema", "pcap-evidence.dnp3-file-reconciliation.v1".into()),
                ("status", "ambiguous".into()),
                (
                    "reason",
                    "one_application_message_contains_multiple_file_handles".into(),
                ),
                ("device_effect_established", false.into()),
            ])));
        }
        let key = touched.into_iter().next();
        let Some(key) = key else { return Ok(None) };
        Ok(Some(self.projection(
            self.states.get(&key).expect("projection state exists"),
            limits,
        )?))
    }

    fn state(&mut self, key: (Scope, u32), function: u8, limits: &Limits) -> Result<&mut State> {
        if !self.states.contains_key(&key) && self.states.len() >= limits.active {
            return Err(Error::limit("dnp_file_sessions"));
        }
        Ok(self.states.entry(key.clone()).or_insert_with(|| State {
            scope: key.0,
            handle: key.1,
            last_function: function,
            request_ids: BTreeSet::new(),
            variations: BTreeSet::new(),
            directions: BTreeSet::new(),
            blocks: BTreeMap::new(),
            duplicate_blocks: BTreeSet::new(),
            conflicting_blocks: BTreeSet::new(),
            status_without_content_blocks: BTreeSet::new(),
            metadata_conflict: false,
            status_codes: BTreeSet::new(),
            declared: None,
            witnesses: Vec::new(),
        }))
    }

    fn projection(&self, state: &State, limits: &Limits) -> Result<Json> {
        if state.blocks.len() > limits.elements
            || state.witnesses.len() > limits.elements
            || state.request_ids.len() > limits.elements
        {
            return Err(Error::limit("dnp_file_projection"));
        }
        let mut content_bytes = 0u64;
        for block in state.blocks.values() {
            content_bytes = content_bytes
                .checked_add(block.length as u64)
                .ok_or_else(|| Error::limit("dnp_file_content_bytes"))?;
        }
        let expected = state
            .declared
            .as_ref()
            .filter(|d| d.maximum_block_size > 0)
            .map(|d| d.file_size.div_ceil(d.maximum_block_size));
        let upper = expected.unwrap_or_else(|| {
            state
                .blocks
                .keys()
                .next_back()
                .map_or(0, |n| u64::from(*n) + 1)
        });
        if upper > limits.elements as u64 {
            return Err(Error::limit("dnp_file_expected_blocks"));
        }
        let mut missing = Vec::new();
        for block in 0..upper {
            if !state.blocks.contains_key(&(block as u32)) {
                if missing.len() >= limits.elements {
                    return Err(Error::limit("dnp_file_missing_blocks"));
                }
                missing.push(block.to_string().into());
            }
        }
        let coverage_complete = state.conflicting_blocks.is_empty()
            && missing.is_empty()
            && state
                .declared
                .as_ref()
                .is_some_and(|d| d.file_size == content_bytes);
        let status = if state.metadata_conflict || !state.conflicting_blocks.is_empty() {
            "ambiguous"
        } else if coverage_complete {
            "candidate_complete_source_coverage"
        } else {
            "incomplete"
        };
        Ok(Json::object([
            ("schema", "pcap-evidence.dnp3-file-reconciliation.v1".into()),
            ("status", status.into()),
            ("session", state.scope.session.to_string().into()),
            ("endpoint_low", state.scope.low.into()),
            ("endpoint_high", state.scope.high.into()),
            ("file_handle", state.handle.into()),
            ("last_function", state.last_function.into()),
            (
                "request_ids",
                Json::array(state.request_ids.iter().map(|n| (*n).into())),
            ),
            (
                "variations",
                Json::array(state.variations.iter().map(|n| (*n).into())),
            ),
            (
                "directions",
                Json::array(state.directions.iter().map(|n| (*n).into())),
            ),
            (
                "status_codes",
                Json::array(state.status_codes.iter().map(|n| (*n).into())),
            ),
            (
                "declared_file_size",
                state
                    .declared
                    .as_ref()
                    .map_or(Json::Null, |d| d.file_size.into()),
            ),
            (
                "maximum_block_size",
                state
                    .declared
                    .as_ref()
                    .map_or(Json::Null, |d| d.maximum_block_size.into()),
            ),
            ("content_bytes_observed", content_bytes.into()),
            (
                "observed_blocks",
                Json::array(state.blocks.iter().map(|(n, b)| {
                    Json::object([
                        ("block", (*n).into()),
                        ("bytes", b.length.into()),
                        ("sha256", b.sha256.clone().into()),
                    ])
                })),
            ),
            (
                "duplicate_blocks",
                Json::array(state.duplicate_blocks.iter().map(|n| (*n).into())),
            ),
            (
                "conflicting_blocks",
                Json::array(state.conflicting_blocks.iter().map(|n| (*n).into())),
            ),
            (
                "status_without_content_blocks",
                Json::array(
                    state
                        .status_without_content_blocks
                        .iter()
                        .map(|n| (*n).into()),
                ),
            ),
            ("metadata_conflict", state.metadata_conflict.into()),
            ("missing_blocks", Json::array(missing)),
            ("witnesses", Json::array(state.witnesses.clone())),
            ("device_effect_established", false.into()),
            (
                "source_binding",
                "current_event_and_retained_capture_witnesses".into(),
            ),
        ]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pcap_evidence::{provenance::PacketId, sha256};

    fn evidence(b: &[u8], frame: u64) -> EvidenceBytes {
        EvidenceBytes::from_packet(
            b,
            PacketId {
                capture: sha256::digest(b"dnp-file-reconciler"),
                frame,
                record_offset: frame * 100,
            },
            0,
        )
    }
    fn status(handle: u32, size: u32, max: u16, request: u16) -> EvidenceBytes {
        let mut b = vec![
            70,
            4,
            0x5b,
            1,
            13,
            0,
            0,
            0,
            0,
            0,
            size as u8,
            (size >> 8) as u8,
            (size >> 16) as u8,
            (size >> 24) as u8,
            max as u8,
            (max >> 8) as u8,
            request as u8,
            (request >> 8) as u8,
            0,
        ];
        b[6..10].copy_from_slice(&handle.to_le_bytes());
        b[10..14].copy_from_slice(&size.to_le_bytes());
        b[14..16].copy_from_slice(&max.to_le_bytes());
        b[16..18].copy_from_slice(&request.to_le_bytes());
        evidence(&b, 1)
    }
    fn block(handle: u32, number: u32, data: &[u8], frame: u64) -> EvidenceBytes {
        let mut b = vec![70, 5, 0x5b, 1, (8 + data.len()) as u8, 0];
        b.extend_from_slice(&handle.to_le_bytes());
        b.extend_from_slice(&number.to_le_bytes());
        b.extend_from_slice(data);
        evidence(&b, frame)
    }
    fn block_status(handle: u32, number: u32, status: u8, frame: u64) -> EvidenceBytes {
        let mut b = vec![70, 6, 0x5b, 1, 9, 0];
        b.extend_from_slice(&handle.to_le_bytes());
        b.extend_from_slice(&number.to_le_bytes());
        b.push(status);
        evidence(&b, frame)
    }

    #[test]
    fn coverage_candidate_requires_contiguous_source_bytes() {
        let mut r = FileReconciler::new();
        let l = Limits::default();
        let e = Json::object([("event", 1u8.into())]);
        let open = status(7, 6, 3, 4);
        r.observe(
            Observation {
                session: 1,
                direction: 0,
                source: 10,
                destination: 20,
                function: 26,
                objects: &open,
                evidence: e.clone(),
            },
            &l,
        )
        .unwrap();
        let first = block(7, 1, b"def", 2);
        let incomplete = r
            .observe(
                Observation {
                    session: 1,
                    direction: 1,
                    source: 20,
                    destination: 10,
                    function: 28,
                    objects: &first,
                    evidence: e.clone(),
                },
                &l,
            )
            .unwrap()
            .unwrap()
            .encode();
        assert!(incomplete.contains("\"status\":\"incomplete\""));
        assert!(incomplete.contains("\"missing_blocks\":[\"0\"]"));
        let second = block(7, 0, b"abc", 3);
        let complete = r
            .observe(
                Observation {
                    session: 1,
                    direction: 1,
                    source: 20,
                    destination: 10,
                    function: 28,
                    objects: &second,
                    evidence: e,
                },
                &l,
            )
            .unwrap()
            .unwrap()
            .encode();
        assert!(complete.contains("candidate_complete_source_coverage"));
        assert!(complete.contains("device_effect_established"));
    }

    #[test]
    fn conflicting_duplicate_is_ambiguous_and_identical_is_retained() {
        let mut r = FileReconciler::new();
        let l = Limits::default();
        let e = Json::Null;
        let open = status(3, 3, 3, 1);
        r.observe(
            Observation {
                session: 1,
                direction: 0,
                source: 10,
                destination: 20,
                function: 26,
                objects: &open,
                evidence: e.clone(),
            },
            &l,
        )
        .unwrap();
        let original = block(3, 0, b"abc", 2);
        r.observe(
            Observation {
                session: 1,
                direction: 1,
                source: 20,
                destination: 10,
                function: 28,
                objects: &original,
                evidence: e.clone(),
            },
            &l,
        )
        .unwrap();
        let duplicate_block = block(3, 0, b"abc", 3);
        let duplicate = r
            .observe(
                Observation {
                    session: 1,
                    direction: 1,
                    source: 20,
                    destination: 10,
                    function: 28,
                    objects: &duplicate_block,
                    evidence: e.clone(),
                },
                &l,
            )
            .unwrap()
            .unwrap()
            .encode();
        assert!(duplicate.contains("\"duplicate_blocks\":[0]"));
        let conflict_block = block(3, 0, b"xyz", 4);
        let conflict = r
            .observe(
                Observation {
                    session: 1,
                    direction: 1,
                    source: 20,
                    destination: 10,
                    function: 28,
                    objects: &conflict_block,
                    evidence: e,
                },
                &l,
            )
            .unwrap()
            .unwrap()
            .encode();
        assert!(conflict.contains("\"status\":\"ambiguous\""));
        assert!(conflict.contains("\"conflicting_blocks\":[0]"));
    }

    #[test]
    fn metadata_and_status_without_content_are_not_block_conflicts() {
        let mut r = FileReconciler::new();
        let l = Limits::default();
        let first = status(9, 3, 3, 1);
        r.observe(
            Observation {
                session: 1,
                direction: 0,
                source: 10,
                destination: 20,
                function: 26,
                objects: &first,
                evidence: Json::Null,
            },
            &l,
        )
        .unwrap();
        let missing_content = block_status(9, 1, 0, 2);
        let status_projection = r
            .observe(
                Observation {
                    session: 1,
                    direction: 1,
                    source: 20,
                    destination: 10,
                    function: 28,
                    objects: &missing_content,
                    evidence: Json::Null,
                },
                &l,
            )
            .unwrap()
            .unwrap()
            .encode();
        assert!(status_projection.contains("\"status_without_content_blocks\":[1]"));
        assert!(!status_projection.contains("\"duplicate_blocks\":[1]"));

        let mismatch = status(9, 4, 3, 2);
        let metadata_projection = r
            .observe(
                Observation {
                    session: 1,
                    direction: 0,
                    source: 10,
                    destination: 20,
                    function: 26,
                    objects: &mismatch,
                    evidence: Json::Null,
                },
                &l,
            )
            .unwrap()
            .unwrap()
            .encode();
        assert!(metadata_projection.contains("\"status\":\"ambiguous\""));
        assert!(metadata_projection.contains("\"metadata_conflict\":true"));
        assert!(!metadata_projection.contains("\"conflicting_blocks\":[4294967295]"));
    }
}
