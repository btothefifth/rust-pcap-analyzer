//! Transactional captured producer. All source identities are caller labels;
//! advertisements and bounded layout interpretations are never negotiated truth.
use super::*;
use pcap_evidence::ErrorCode;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct SessionScope {
    source_id: String,
    session: u64,
    capture: [u8; 32],
}

/// No OPEN payload is retained: unknown parameters/capabilities are hash-only.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct OpenWitness {
    pub(super) value: Json,
    encoded_bytes: usize,
    nodes: usize,
    references: usize,
}

/// Parsed advertisements from one OPEN, never a negotiated endpoint state.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(super) struct CapabilitySet {
    pub four_octet_asn: Option<u32>,
    pub mp: BTreeSet<(u16, u8)>,
    pub add_path: BTreeMap<(u16, u8), u8>,
    pub add_path_malformed: bool,
    pub extended_messages: bool,
    pub enhanced_refresh: bool,
    pub valid: bool,
}

#[derive(Debug, Default)]
struct Size {
    nodes: usize,
    references: usize,
    encoded_bound: usize,
}

/// Conservative logical accounting. This is not an allocator or CPU sandbox.
pub(super) struct Budget<'a> {
    limits: &'a Limits,
    work: usize,
}
impl<'a> Budget<'a> {
    pub(super) fn new(limits: &'a Limits) -> Self {
        Self { limits, work: 0 }
    }
    pub(super) fn charge(&mut self, amount: usize) -> Result<()> {
        self.work = add(self.work, amount)?;
        cap(self.work, self.limits.work, "bgp_producer_work")
    }
    fn tree(&mut self, value: &Json) -> Result<Size> {
        fn walk(
            value: &Json,
            depth: usize,
            size: &mut Size,
            budget: &mut Budget<'_>,
        ) -> Result<()> {
            cap(depth, budget.limits.depth, "bgp_producer_depth")?;
            size.nodes = add(size.nodes, 1)?;
            cap(size.nodes, budget.limits.fields, "bgp_producer_fields")?;
            budget.charge(1)?;
            size.encoded_bound = add(size.encoded_bound, 24)?;
            match value {
                Json::String(s) => {
                    cap(s.len(), budget.limits.input_bytes, "bgp_producer_string")?;
                    budget.charge(s.len())?;
                    size.encoded_bound = add(size.encoded_bound, mul(s.len(), 6)?)?;
                }
                Json::Array(items) => {
                    cap(items.len(), budget.limits.fields, "bgp_producer_fields")?;
                    for v in items {
                        walk(v, depth + 1, size, budget)?;
                    }
                }
                Json::Object(items) => {
                    cap(items.len(), budget.limits.fields, "bgp_producer_fields")?;
                    let mut keys = BTreeSet::new();
                    for (key, v) in items {
                        budget.charge(key.len())?;
                        if !keys.insert(*key) {
                            return Err(bad(
                                "bgp_producer_duplicate_key",
                                0,
                                "duplicate output key",
                            ));
                        }
                        size.encoded_bound = add(size.encoded_bound, mul(key.len(), 6)?)?;
                        if matches!(*key, "spans" | "packets") {
                            if let Json::Array(refs) = v {
                                size.references = add(size.references, refs.len())?;
                                cap(size.references, budget.limits.spans, "bgp_producer_spans")?;
                            }
                        }
                        walk(v, depth + 1, size, budget)?;
                    }
                }
                _ => {}
            }
            Ok(())
        }
        let mut size = Size::default();
        walk(value, 1, &mut size, self)?;
        Ok(size)
    }
    fn encode(&mut self, value: &Json, max: usize) -> Result<(String, Size)> {
        let size = self.tree(value)?;
        // Reserve escaping, traversal and serialization work before encoding.
        self.charge(size.encoded_bound)?;
        Ok((value.encode_bounded(max)?, size))
    }
    fn state(&mut self, state: &SessionState) -> Result<usize> {
        cap(state.opens.len(), self.limits.active, "bgp_producer_active")?;
        let mut bytes = 64usize;
        let mut nodes = 0usize;
        let mut refs = 0usize;
        let mut occurrences = 0usize;
        if let Some(scope) = &state.scope {
            identity(&scope.source_id, self.limits)?;
            bytes = add(bytes, scope.source_id.len())?;
        }
        for open in state.opens.values().flatten() {
            occurrences = add(occurrences, 1)?;
            nodes = add(nodes, open.witness.nodes)?;
            refs = add(refs, open.witness.references)?;
            // Include typed lookup structures as well as the immutable JSON witness.
            let lookups = add(
                mul(open.capabilities.mp.len(), 48)?,
                mul(open.capabilities.add_path.len(), 64)?,
            )?;
            bytes = add(bytes, add(add(open.witness.encoded_bytes, 256)?, lookups)?)?;
        }
        cap(
            occurrences,
            self.limits.elements,
            "bgp_producer_open_records",
        )?;
        cap(nodes, self.limits.fields, "bgp_producer_fields")?;
        cap(refs, self.limits.spans, "bgp_producer_spans")?;
        cap(bytes, self.limits.retained_bytes, "bgp_producer_retained")?;
        self.charge(mul(bytes, 4)?)?;
        Ok(bytes)
    }
    pub(super) fn routes(
        &mut self,
        count: usize,
        attrs: &PathAttributes,
        ranges: &[AttributeRange],
    ) -> Result<()> {
        cap(count, self.limits.elements, "bgp_producer_routes")?;
        let fields = attributes_json(attrs);
        let (encoded, stats) = self.encode(&fields, self.limits.input_bytes)?;
        let mut nodes = add(stats.nodes, 12)?;
        let mut bytes = add(encoded.len(), 256)?;
        let mut values = attrs.as_path.len();
        for segment in &attrs.as_path {
            values = add(values, segment.values.len())?;
        }
        for n in [
            attrs.communities.len(),
            attrs.cluster_list.len(),
            attrs.mp_reach.len(),
            attrs.mp_unreach.len(),
            ranges.len(),
        ] {
            values = add(values, n)?;
        }
        cap(
            values,
            self.limits.elements,
            "bgp_producer_attribute_values",
        )?;
        for range in ranges {
            let (v, s) = self.encode(&range.value, self.limits.input_bytes)?;
            nodes = add(nodes, add(s.nodes, 12)?)?;
            bytes = add(bytes, add(v.len(), 512)?)?;
        }
        // Bound per-route attribute replication BEFORE cloning typed records.
        cap(
            mul(nodes, add(count, 1)?)?,
            self.limits.fields,
            "bgp_producer_route_fields",
        )?;
        cap(
            mul(bytes, add(count, 1)?)?,
            self.limits.retained_bytes,
            "bgp_producer_route_retained",
        )?;
        self.charge(mul(mul(bytes, add(count, 1)?)?, 4)?)
    }
}

fn add(a: usize, b: usize) -> Result<usize> {
    a.checked_add(b)
        .ok_or_else(|| Error::limit("bgp_producer_arithmetic"))
}
fn mul(a: usize, b: usize) -> Result<usize> {
    a.checked_mul(b)
        .ok_or_else(|| Error::limit("bgp_producer_arithmetic"))
}
fn cap(value: usize, limit: usize, field: &'static str) -> Result<()> {
    if value > limit {
        Err(Error::limit(field))
    } else {
        Ok(())
    }
}
fn identity(value: &str, limits: &Limits) -> Result<()> {
    cap(
        value.len(),
        limits.input_bytes.min(1024),
        "bgp_producer_identity_bytes",
    )?;
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(bad(
            "bgp_producer_identity",
            0,
            "nonempty control-free identity required",
        ));
    }
    Ok(())
}
fn metadata_json(m: &PcapMetadata) -> Json {
    Json::object([
        ("source_id", m.source_id.clone().into()),
        ("record_id", m.record_id.clone().into()),
        (
            "session",
            m.session.map_or(Json::Null, |s| s.to_string().into()),
        ),
        ("direction", m.direction.map_or(Json::Null, Json::from)),
        ("peer", m.peer.clone().map_or(Json::Null, Json::from)),
        ("local", m.local.clone().map_or(Json::Null, Json::from)),
        (
            "observed_at_ns",
            m.observed_at_ns
                .map_or(Json::Null, |n| n.to_string().into()),
        ),
    ])
}
fn member<'a>(v: &'a Json, key: &str) -> Option<&'a Json> {
    if let Json::Object(fields) = v {
        fields
            .iter()
            .find(|(name, _)| *name == key)
            .map(|(_, value)| value)
    } else {
        None
    }
}
fn set(value: &mut Json, key: &'static str, replacement: Json) {
    if let Json::Object(fields) = value {
        if let Some((_, old)) = fields.iter_mut().find(|(name, _)| *name == key) {
            *old = replacement;
        } else {
            fields.push((key, replacement));
        }
    }
}
fn canonical_json(v: &Json) -> Json {
    match v {
        Json::Object(fields) => {
            let mut fields: Vec<_> = fields
                .iter()
                .map(|(k, v)| (*k, canonical_json(v)))
                .collect();
            fields.sort_by_key(|(key, _)| *key);
            Json::Object(fields)
        }
        Json::Array(items) => Json::array(items.iter().map(canonical_json)),
        _ => v.clone(),
    }
}

fn tuple_range(start: usize, end: usize) -> Json {
    Json::object([("start", start.into()), ("end", end.into())])
}

/// Decode only grammars declared by this producer. The enclosing occurrence
/// always carries the original byte range and digest, including invalid data.
fn capability_value(code: u8, value: &[u8], start: usize) -> (Json, Json, &'static str) {
    let len = value.len();
    let invalid = |reason| (Json::Null, Json::from(false), reason);
    match code {
        1 if len == 4 => (
            Json::object([
                ("kind", "multiprotocol".into()),
                ("afi", u16::from_be_bytes([value[0], value[1]]).into()),
                ("reserved", value[2].into()),
                ("safi", value[3].into()),
                ("range", tuple_range(start, start + 4)),
            ]),
            true.into(),
            "valid",
        ),
        1 => invalid("invalid_length"),
        2 | 6 | 70 if len == 0 => (
            Json::object([(
                "kind",
                match code {
                    2 => "route_refresh",
                    6 => "extended_messages",
                    _ => "enhanced_route_refresh",
                }
                .into(),
            )]),
            true.into(),
            "valid",
        ),
        2 | 6 | 70 => invalid("invalid_length"),
        65 if len == 4 && value == [0, 0, 0, 0] => invalid("as_zero"),
        65 if len == 4 => (
            u32::from_be_bytes([value[0], value[1], value[2], value[3]]).into(),
            true.into(),
            "valid",
        ),
        65 => invalid("invalid_length"),
        64 if len >= 2 && (len - 2) % 4 == 0 => {
            let header = u16::from_be_bytes([value[0], value[1]]);
            let families = Json::array(value[2..].chunks_exact(4).enumerate().map(|(i, tuple)| {
                Json::object([
                    ("afi", u16::from_be_bytes([tuple[0], tuple[1]]).into()),
                    ("safi", tuple[2].into()),
                    ("flags", tuple[3].into()),
                    ("forwarding_state", (tuple[3] & 0x80 != 0).into()),
                    ("range", tuple_range(start + 2 + i * 4, start + 6 + i * 4)),
                ])
            }));
            (
                Json::object([
                    ("kind", "graceful_restart".into()),
                    ("restart_flags", ((header >> 12) as u8).into()),
                    ("restart_state", (header & 0x8000 != 0).into()),
                    ("restart_time_seconds", (header & 0x0fff).into()),
                    ("families", families),
                ]),
                true.into(),
                "valid",
            )
        }
        64 => invalid("invalid_length"),
        71 if len % 7 == 0 => {
            let families = Json::array(value.chunks_exact(7).enumerate().map(|(i, tuple)| {
                Json::object([
                    ("afi", u16::from_be_bytes([tuple[0], tuple[1]]).into()),
                    ("safi", tuple[2].into()),
                    ("flags", tuple[3].into()),
                    ("forwarding_state", (tuple[3] & 0x80 != 0).into()),
                    (
                        "stale_time_seconds",
                        ((u32::from(tuple[4]) << 16)
                            | (u32::from(tuple[5]) << 8)
                            | u32::from(tuple[6]))
                        .into(),
                    ),
                    ("range", tuple_range(start + i * 7, start + (i + 1) * 7)),
                ])
            }));
            (
                Json::object([
                    ("kind", "long_lived_graceful_restart".into()),
                    ("families", families),
                ]),
                true.into(),
                "valid",
            )
        }
        71 => invalid("invalid_length"),
        69 if len >= 4
            && len % 4 == 0
            && value
                .chunks_exact(4)
                .all(|tuple| (1..=3).contains(&tuple[3])) =>
        {
            let families = Json::array(value.chunks_exact(4).enumerate().map(|(i, tuple)| {
                Json::object([
                    ("afi", u16::from_be_bytes([tuple[0], tuple[1]]).into()),
                    ("safi", tuple[2].into()),
                    ("mode", tuple[3].into()),
                    ("receive", (tuple[3] & 1 != 0).into()),
                    ("send", (tuple[3] & 2 != 0).into()),
                    ("range", tuple_range(start + i * 4, start + (i + 1) * 4)),
                ])
            }));
            (
                Json::object([("kind", "add_path".into()), ("families", families)]),
                true.into(),
                "valid",
            )
        }
        69 if len == 0 || len % 4 != 0 => invalid("invalid_length"),
        69 => invalid("invalid_send_receive"),
        9 if len == 1 && value[0] <= 4 => (
            Json::object([("kind", "role".into()), ("role", value[0].into())]),
            true.into(),
            "valid",
        ),
        9 if len != 1 => invalid("invalid_length"),
        9 => invalid("unassigned_role_value"),
        _ => (Json::Null, Json::Null, "unknown_capability"),
    }
}

/// An offline grammar hypothesis requires one complete, unambiguous OPEN on
/// each side of the same source/session. It establishes no endpoint state.
pub(super) fn layout_evidence(state: &SessionState, scoped: bool) -> (LayoutContext, &'static str) {
    let mut context = LayoutContext {
        peer_relationship: state.peer_relationship,
        peer_relationship_configured: state.peer_relationship_configured,
        ..LayoutContext::default()
    };
    let families = [(1u16, 1u8), (1, 2), (2, 1), (2, 2)];
    let unresolved = |context: &mut LayoutContext| {
        let mut observed = BTreeSet::new();
        for open in state.opens.values().flatten() {
            observed.extend(open.capabilities.add_path.keys().copied());
            if open.capabilities.add_path_malformed {
                observed.extend(families);
            }
        }
        for sender in [0, 1] {
            for (afi, safi) in &observed {
                context.unresolved_add_path.insert((sender, *afi, *safi));
            }
        }
    };
    if !scoped {
        return (context, "missing_scope");
    }
    if state
        .opens
        .values()
        .any(|opens| opens.len() != 1 || opens[0].ambiguous || !opens[0].capabilities.valid)
    {
        unresolved(&mut context);
        return (context, "ambiguous_open_evidence");
    }
    let (Some(a), Some(b)) = (state.opens.get(&0), state.opens.get(&1)) else {
        unresolved(&mut context);
        return (context, "missing_open_evidence");
    };
    let (a, b) = (&a[0].capabilities, &b[0].capabilities);
    context.asn_width = if a.four_octet_asn.is_some() && b.four_octet_asn.is_some() {
        4
    } else {
        2
    };
    context.mp = a.mp.intersection(&b.mp).copied().collect();
    context.extended_messages = a.extended_messages && b.extended_messages;
    if b.extended_messages {
        context.extended_message_senders.insert(0);
    }
    if a.extended_messages {
        context.extended_message_senders.insert(1);
    }
    context.enhanced_refresh = a.enhanced_refresh && b.enhanced_refresh;
    let advertised: BTreeSet<_> = a
        .add_path
        .keys()
        .chain(b.add_path.keys())
        .copied()
        .collect();
    for (afi, safi) in advertised {
        let a_mode = a.add_path.get(&(afi, safi)).copied();
        let b_mode = b.add_path.get(&(afi, safi)).copied();
        match (a_mode, b_mode) {
            (Some(a), Some(b)) => {
                if a & 2 != 0 && b & 1 != 0 {
                    context.add_path.insert((0, afi, safi));
                }
                if b & 2 != 0 && a & 1 != 0 {
                    context.add_path.insert((1, afi, safi));
                }
            }
            _ => {
                context.unresolved_add_path.insert((0, afi, safi));
                context.unresolved_add_path.insert((1, afi, safi));
            }
        }
    }
    let basis = if context.asn_width == 4 {
        "both_four_octet_advertisements"
    } else {
        "two_octet_bilateral_advertisements"
    };
    (context, basis)
}
fn session_json(state: &SessionState, scoped: bool) -> Json {
    let (context, basis) = layout_evidence(state, scoped);
    let width = context.asn_width;
    Json::object([
        ("schema", "pcap-evidence.bgp.producer-context.v1".into()),
        ("scope_bound", scoped.into()),
        (
            "asn_width",
            if width == 0 { Json::Null } else { width.into() },
        ),
        ("asn_width_basis", basis.into()),
        (
            "capability_layout",
            Json::object([
                (
                    "multiprotocol",
                    Json::array(context.mp.iter().map(|(afi, safi)| {
                        Json::object([("afi", (*afi).into()), ("safi", (*safi).into())])
                    })),
                ),
                (
                    "add_path",
                    Json::array(context.add_path.iter().map(|(direction, afi, safi)| {
                        Json::object([
                            ("direction", (*direction).into()),
                            ("afi", (*afi).into()),
                            ("safi", (*safi).into()),
                        ])
                    })),
                ),
                (
                    "unresolved_add_path",
                    Json::array(context.unresolved_add_path.iter().map(
                        |(direction, afi, safi)| {
                            Json::object([
                                ("direction", (*direction).into()),
                                ("afi", (*afi).into()),
                                ("safi", (*safi).into()),
                            ])
                        },
                    )),
                ),
                ("extended_messages", context.extended_messages.into()),
                (
                    "extended_message_senders",
                    Json::array(
                        context
                            .extended_message_senders
                            .iter()
                            .map(|direction| (*direction).into()),
                    ),
                ),
                ("enhanced_refresh", context.enhanced_refresh.into()),
                ("basis", basis.into()),
            ]),
        ),
        (
            "open_sides",
            if scoped {
                Json::array(state.opens.iter().map(|(direction, opens)| {
                    Json::object([
                        ("direction", (*direction).into()),
                        (
                            "advertised_asn_width",
                            if opens.len() == 1 && !opens[0].ambiguous {
                                state.asn_width(*direction).into()
                            } else {
                                Json::Null
                            },
                        ),
                        (
                            "observations",
                            Json::array(opens.iter().map(|o| o.witness.value.clone())),
                        ),
                    ])
                }))
            } else {
                Json::Array(Vec::new())
            },
        ),
        ("negotiation_established", false.into()),
        ("endpoint_state_established", false.into()),
        ("source_authority_established", false.into()),
        ("causality_established", false.into()),
    ])
}

pub(super) fn decode(
    bytes: &EvidenceBytes,
    metadata: PcapMetadata,
    state: &mut SessionState,
    limits: &Limits,
) -> Result<Json> {
    limits.validate()?;
    let mut budget = Budget::new(limits);
    cap(bytes.len(), limits.input_bytes, "bgp_producer_input")?;
    cap(bytes.spans().len(), limits.spans, "bgp_producer_spans")?;
    let mut metadata_bytes = 0usize;
    for value in [&metadata.source_id, &metadata.record_id]
        .into_iter()
        .chain(metadata.peer.iter())
        .chain(metadata.local.iter())
    {
        identity(value, limits)?;
        metadata_bytes = add(metadata_bytes, value.len())?;
    }
    cap(metadata_bytes, limits.input_bytes, "bgp_producer_metadata")?;
    if metadata.direction.is_some_and(|d| d > 1) {
        return Err(bad(
            "bgp_producer_direction",
            0,
            "captured direction must be zero or one",
        ));
    }
    // Reserve validation and bounded scanner passes before accessing wire data.
    budget.charge(add(
        mul(bytes.len(), 32)?,
        add(metadata_bytes, mul(bytes.spans().len(), 256)?)?,
    )?)?;
    if !bytes.validate() || bytes.spans().iter().any(|s| s.packet.frame == 0) {
        return Err(bad("bgp_provenance", 0, "invalid source evidence"));
    }
    let b = bytes.data();
    let scoped = metadata.session.is_some() && metadata.direction.is_some();
    let (prior_layout, _) = layout_evidence(state, scoped);
    let extended_message = metadata
        .direction
        .is_some_and(|direction| prior_layout.extended_message_senders.contains(&direction));
    validate_message_frame(b, extended_message)?;
    let capture = bytes
        .spans()
        .first()
        .ok_or_else(|| bad("bgp_provenance", 0, "missing packet witness"))?
        .packet
        .capture;
    if bytes.spans().iter().any(|s| s.packet.capture != capture) {
        return Err(bad("bgp_producer_capture", 0, "mixed capture namespaces"));
    }
    cap(
        add(bytes.spans().len(), bytes.packets().len())?,
        limits.spans,
        "bgp_producer_spans",
    )?;
    let scope = metadata.session.map(|session| SessionScope {
        source_id: metadata.source_id.clone(),
        session,
        capture,
    });
    if let (Some(old), Some(current)) = (&state.scope, &scope) {
        if old != current {
            return Err(bad(
                "bgp_producer_session",
                0,
                "state belongs to another source/session/capture",
            ));
        }
    }
    budget.state(state)?; // Recheck retained state under the caller's current limits.
    let mut next = state.clone();
    if (scoped || b[18] == 3 && metadata.session.is_some()) && next.scope.is_none() {
        next.scope = scope;
    }
    let mut issues = Vec::new();
    if metadata.direction.is_none() {
        issues.push(if b[18] == 3 && metadata.session.is_some() {
            "direction_missing_notification_closes_scoped_generation"
        } else {
            "direction_missing_state_not_updated"
        });
    }
    if metadata.session.is_none() {
        issues.push("session_missing_state_not_updated");
    }
    let mut records = Vec::new();
    let mut message_detail = None;
    let mut reset_after = false;
    match b[18] {
        1 => {
            let open = parse_open(bytes, &metadata, limits, &mut budget)?;
            issues.extend(open.capability_issues.iter().copied());
            message_detail = member(&open.witness.value, "open").cloned();
            if scoped {
                let direction = metadata
                    .direction
                    .ok_or_else(|| bad("bgp_producer_direction", 0, "direction missing"))?;
                let old = next.opens.get(&direction);
                let identical = old.is_some_and(|items| {
                    items.iter().any(|o| o.witness.value == open.witness.value)
                });
                if !identical {
                    if old.is_some() {
                        issues.push("repeated_open_requires_explicit_generation_boundary");
                    }
                    cap(
                        next.opens
                            .values()
                            .map(Vec::len)
                            .sum::<usize>()
                            .saturating_add(1),
                        limits.elements,
                        "bgp_producer_open_records",
                    )?;
                    if old.is_none() {
                        cap(next.opens.len() + 1, limits.active, "bgp_producer_active")?;
                    }
                    next.opens.entry(direction).or_default().push(open);
                }
            }
        }
        2 => {
            let (layout, basis) = layout_evidence(&next, scoped);
            let mut parsed = parse_update(b, &layout, metadata.direction, limits, &mut budget)?;
            if scoped
                && next.opens.values().flatten().any(|o| {
                    o.capability_issues.iter().any(|issue| {
                        matches!(
                            *issue,
                            "unsupported_capability_retained_by_hash"
                                | "unsupported_open_parameter_retained_by_hash"
                        )
                    })
                })
            {
                parsed
                    .issues
                    .push("unsupported_session_capabilities_not_interpreted");
            }
            if basis == "ambiguous_open_evidence" {
                parsed.issues.push("capability_context_unresolved");
                for range in &mut parsed.attribute_ranges {
                    if matches!(range.code, 2 | 7) {
                        range.interpretation = "unresolved_capability_context";
                    }
                }
                for record in &mut parsed.records {
                    record.attributes.as_path.clear();
                    record.attributes.aggregator = None;
                    for range in &mut record.attribute_ranges {
                        if matches!(range.code, 2 | 7) {
                            range.interpretation = "unresolved_capability_context";
                        }
                    }
                }
            }
            records = parsed.records;
            issues.extend(parsed.issues);
            let path_replacement_performed = matches!(
                member(&parsed.as4_reconstruction, "status"),
                Some(Json::String(status)) if status.starts_with("old_new_reconstructed")
            );
            message_detail = Some(Json::object([
                (
                    "attribute_ranges",
                    Json::array(parsed.attribute_ranges.iter().map(attribute_range_json)),
                ),
                ("update_disposition", parsed.disposition.into()),
                ("known_update_disposition", parsed.known_disposition.into()),
                (
                    "peer_relationship",
                    parsed.peer_relationship.as_str().into(),
                ),
                (
                    "peer_relationship_basis",
                    parsed.peer_relationship_basis.into(),
                ),
                (
                    "peer_relationship_unresolved",
                    parsed.peer_relationship_unresolved.into(),
                ),
                (
                    "end_of_rib",
                    Json::array(parsed.end_of_rib.iter().map(|(afi, safi)| {
                        Json::object([("afi", (*afi).into()), ("safi", (*safi).into())])
                    })),
                ),
                ("as4_reconstruction", parsed.as4_reconstruction.clone()),
                ("opaque_nlri", Json::Array(parsed.opaque_nlri.clone())),
                (
                    "missing_mandatory",
                    Json::array(parsed.missing_mandatory.iter().map(|code| (*code).into())),
                ),
                (
                    "path_replacement_performed",
                    path_replacement_performed.into(),
                ),
            ]));
            if parsed.known_disposition == "session_reset" && metadata.session.is_some() {
                reset_after = true;
            }
        }
        3 => {
            need(b, 21, "bgp_notification")?;
            let mut detail = notification_detail(b);
            set(
                &mut detail,
                "field_ranges",
                Json::array([
                    field("code", 19, 20),
                    field("subcode", 20, 21),
                    field("data_sha256", 21, b.len()),
                ]),
            );
            message_detail = Some(detail);
            reset_after = metadata.session.is_some();
        }
        4 => {
            if b.len() != 19 {
                return Err(bad("bgp_keepalive", 16, "KEEPALIVE must be 19 bytes"));
            }
        }
        5 => {
            if b.len() != 23 {
                return Err(bad("bgp_route_refresh", 16, "invalid ROUTE-REFRESH length"));
            }
            let mut detail = route_refresh_detail(b)?;
            set(
                &mut detail,
                "field_ranges",
                Json::array([
                    field("afi", 19, 21),
                    field("reserved", 21, 22),
                    field("safi", 22, 23),
                ]),
            );
            let enhanced_layout = layout_evidence(&next, scoped).0.enhanced_refresh;
            set(
                &mut detail,
                "enhanced_layout_context",
                enhanced_layout.into(),
            );
            if matches!(b[21], 1 | 2) && !enhanced_layout {
                issues.push("enhanced_route_refresh_unresolved_context");
            }
            if b[21] > 2 {
                issues.push("unknown_route_refresh_subtype_retained");
            }
            message_detail = Some(detail);
        }
        _ => return Err(bad("bgp_type", 18, "unsupported BGP message type")),
    }
    cap(records.len(), limits.elements, "bgp_producer_routes")?;
    cap(
        add(issues.len(), 2)?,
        limits.elements,
        "bgp_producer_issues",
    )?;
    budget.state(&next)?;
    let producer_context = session_json(&next, scoped);
    let generation = next.generation;
    let source = Source {
        kind: SourceKind::Captured,
        source_id: metadata.source_id,
        record_id: metadata.record_id,
        observed_at_ns: metadata.observed_at_ns,
        session: metadata.session.map(|n| n.to_string()),
        direction: metadata.direction,
        peer: metadata.peer,
        local: metadata.local,
    };
    let generation_known = source.session.is_some();
    let mut output = envelope(
        source,
        generation,
        b[18],
        records,
        issues,
        EnvelopeDetails {
            message_detail,
            evidence: Some(pcap_evidence(bytes)),
            import_context: None,
        },
        limits,
    )?;
    if !generation_known {
        set(&mut output, "generation", Json::Null);
    }
    set(&mut output, "producer_context", producer_context);
    for name in [
        "rib_established",
        "best_path_selected",
        "reachability_established",
        "attack_established",
        "source_authority_established",
        "normative_conformance_certified",
        "negotiation_established",
    ] {
        set(&mut output, name, false.into());
    }
    // State transitions are staged until exact complete output sizing succeeds.
    if reset_after {
        next.reset()?;
    }
    let retained = budget.state(&next)?;
    let (encoded, _) = budget.encode(&output, limits.input_bytes.min(limits.output_bytes))?;
    cap(
        add(retained, encoded.len())?,
        limits.retained_bytes,
        "bgp_producer_retained",
    )?;
    budget.charge(mul(encoded.len(), 2)?)?;
    let output = canonical_json(&output);
    *state = next;
    Ok(output)
}

fn field(name: &'static str, start: usize, end: usize) -> Json {
    Json::object([
        ("name", name.into()),
        ("start", start.into()),
        ("end", end.into()),
    ])
}

/// Validate the common BGP message frame without introducing capture evidence.
/// The caller supplies only the capability-derived extended-message bound.
pub(super) fn validate_message_frame(b: &[u8], extended_message: bool) -> Result<u8> {
    need(b, 19, "bgp_header")?;
    if b[..16] != [255; 16] {
        return Err(bad("bgp_marker", 0, "invalid marker"));
    }
    let length = usize::from(be16(b, 16)?);
    let message_type = b[18];
    let limit = if extended_message && !matches!(message_type, 1 | 4) {
        65535
    } else {
        4096
    };
    if !(19..=limit).contains(&length) {
        return Err(bad(
            "bgp_length",
            16,
            "length outside supported capability boundary",
        ));
    }
    need(b, length, "bgp_message")?;
    if b.len() != length {
        return Err(bad(
            "bgp_message",
            length,
            "expected exactly one framed message",
        ));
    }
    Ok(message_type)
}

fn parse_open(
    bytes: &EvidenceBytes,
    metadata: &PcapMetadata,
    limits: &Limits,
    budget: &mut Budget<'_>,
) -> Result<OpenState> {
    parse_open_body(
        bytes.data(),
        metadata_json(metadata),
        pcap_evidence(bytes),
        limits,
        budget,
    )
}

pub(super) fn parse_open_imported(
    b: &[u8],
    source: Json,
    evidence: Json,
    limits: &Limits,
) -> Result<OpenState> {
    let mut budget = Budget::new(limits);
    parse_open_body(b, source, evidence, limits, &mut budget)
}

fn parse_open_body(
    b: &[u8],
    source: Json,
    evidence: Json,
    limits: &Limits,
    budget: &mut Budget<'_>,
) -> Result<OpenState> {
    need(b, 29, "bgp_open")?;
    if b[19] != 4 {
        return Err(bad("bgp_version", 19, "only BGP-4 is supported"));
    }
    let extended_options = b[28] != 0 && b.get(29) == Some(&255);
    let (parameters_start, parameters_length, parameter_header) = if extended_options {
        need(b, 32, "bgp_open_extended_options")?;
        (32, usize::from(be16(b, 30)?), 3)
    } else {
        (29, usize::from(b[28]), 2)
    };
    if parameters_start + parameters_length != b.len() {
        return Err(bad(
            "bgp_open_options",
            28,
            "optional extent does not fill OPEN",
        ));
    }
    let mut capabilities = Vec::new();
    let mut parameters = Vec::new();
    let mut occurrences = Vec::new();
    let mut seen: BTreeMap<u8, BTreeSet<String>> = BTreeMap::new();
    let mut four = None;
    let mut ambiguous = false;
    let mut capability_set = CapabilitySet {
        valid: true,
        ..CapabilitySet::default()
    };
    let mut issues = Vec::new();
    let mut p = parameters_start;
    while p < b.len() {
        need(b, p + parameter_header, "bgp_open_parameter")?;
        let parameter_length = if extended_options {
            usize::from(be16(b, p + 1)?)
        } else {
            usize::from(b[p + 1])
        };
        let end = p + parameter_header + parameter_length;
        if end > b.len() {
            return Err(bad("bgp_open_parameter", p, "parameter exceeds OPEN"));
        }
        cap(
            parameters.len() + occurrences.len() + 1,
            limits.elements,
            "bgp_producer_parameters",
        )?;
        parameters.push(Json::object([
            ("type", b[p].into()),
            ("start", p.into()),
            ("end", end.into()),
            ("value_start", (p + parameter_header).into()),
            (
                "sha256",
                payload_sha256(&b[p + parameter_header..end]).into(),
            ),
            (
                "interpretation",
                if b[p] == 2 {
                    "capability_envelope"
                } else {
                    "unsupported_hash_only"
                }
                .into(),
            ),
        ]));
        if b[p] == 2 {
            let mut q = p + parameter_header;
            while q < end {
                if q + 2 > end {
                    return Err(bad(
                        "bgp_capability",
                        q,
                        "capability header exceeds parameter",
                    ));
                }
                let code = b[q];
                let length = usize::from(b[q + 1]);
                let value_start = q + 2;
                let value_end = value_start + length;
                if value_end > end {
                    return Err(bad("bgp_capability", q, "capability exceeds parameter"));
                }
                budget.charge(
                    occurrences
                        .len()
                        .saturating_mul(70)
                        .saturating_add(length.saturating_mul(16))
                        .saturating_add(256),
                )?;
                cap(
                    occurrences.len() + parameters.len() + 1,
                    limits.elements,
                    "bgp_producer_capabilities",
                )?;
                let hash = payload_sha256(&b[value_start..value_end]);
                let prior = seen.get(&code);
                let repetition = match prior {
                    None => "first",
                    Some(previous) if previous.len() == 1 && previous.contains(&hash) => {
                        "duplicate_identical"
                    }
                    Some(_) => "conflicting",
                };
                if prior.is_some() {
                    issues.push("duplicate_capability_code");
                }
                if repetition == "conflicting" {
                    issues.push("conflicting_capability_values");
                    if matches!(code, 6 | 9 | 65 | 69) {
                        ambiguous = true;
                    }
                }
                seen.entry(code).or_default().insert(hash.clone());
                let (value, valid, reason) =
                    capability_value(code, &b[value_start..value_end], value_start);
                if valid == Json::from(false) {
                    capability_set.valid = false;
                    ambiguous = true;
                    issues.push("invalid_declared_capability_retained");
                    if code == 69 {
                        capability_set.add_path_malformed = true;
                    }
                }
                if valid == Json::Null {
                    issues.push("unsupported_capability_retained_by_hash");
                } else if valid == Json::from(true) {
                    match code {
                        1 => {
                            capability_set
                                .mp
                                .insert((be16(b, value_start)?, b[value_start + 3]));
                        }
                        6 => capability_set.extended_messages = true,
                        70 => capability_set.enhanced_refresh = true,
                        65 => {
                            let asn = be32(b, value_start)?;
                            if four.is_none() {
                                four = Some(asn);
                            }
                            capability_set.four_octet_asn = Some(asn);
                        }
                        69 => {
                            for tuple in b[value_start..value_end].chunks_exact(4) {
                                let family = (u16::from_be_bytes([tuple[0], tuple[1]]), tuple[2]);
                                if capability_set
                                    .add_path
                                    .insert(family, tuple[3])
                                    .is_some_and(|old| old != tuple[3])
                                {
                                    issues.push("conflicting_add_path_family");
                                    ambiguous = true;
                                }
                            }
                        }
                        _ => {}
                    }
                }
                capabilities.push(code);
                occurrences.push(Json::object([
                    ("code", code.into()),
                    ("length", length.into()),
                    ("start", q.into()),
                    ("end", value_end.into()),
                    ("value_start", value_start.into()),
                    ("value_end", value_end.into()),
                    ("parameter_start", p.into()),
                    ("parameter_end", end.into()),
                    ("sha256", hash.into()),
                    ("decoded", value),
                    ("valid", valid),
                    (
                        "invalid_reason",
                        if reason == "valid" || reason == "unknown_capability" {
                            Json::Null
                        } else {
                            reason.into()
                        },
                    ),
                    ("repetition", repetition.into()),
                    (
                        "interpretation",
                        if reason == "unknown_capability" {
                            "unsupported_hash_only"
                        } else if reason == "valid" {
                            "advertised_not_negotiated"
                        } else {
                            "invalid_retained_by_hash"
                        }
                        .into(),
                    ),
                ]));
                q = value_end;
            }
        } else {
            issues.push("unsupported_open_parameter_retained_by_hash");
        }
        p = end;
    }
    if seen.get(&65).is_some_and(|values| values.len() > 1) {
        four = None;
        capability_set.four_octet_asn = None;
    }
    if seen.contains_key(&71) && !seen.contains_key(&64) {
        issues.push("llgr_without_gr_disregarded");
    }
    let autonomous_system = be16(b, 20)?;
    let hold_time = be16(b, 22)?;
    if autonomous_system == 0 {
        issues.push("open_peer_as_zero");
        ambiguous = true;
    }
    if hold_time == 0 {
        issues.push("hold_time_zero");
    }
    if matches!(hold_time, 1 | 2) {
        issues.push("open_hold_time_invalid_for_base_subset");
        ambiguous = true;
    }
    if four.is_some_and(|asn| {
        if asn <= u32::from(u16::MAX) {
            asn != u32::from(autonomous_system)
        } else {
            autonomous_system != 23456
        }
    }) {
        issues.push("open_asn_fields_inconsistent");
        ambiguous = true;
    }
    cap(issues.len(), limits.elements, "bgp_producer_issues")?;
    let identifier_value = be32(b, 24)?;
    let identifier_address = Ipv4Addr::from(identifier_value);
    if identifier_value == 0
        || identifier_address.is_multicast()
        || identifier_address.is_broadcast()
    {
        return Err(bad(
            "bgp_identifier",
            24,
            "BGP Identifier must be a nonzero unicast IPv4 address",
        ));
    }
    let identifier = identifier_address.to_string();
    let detail = Json::object([
        ("version", 4u8.into()),
        ("autonomous_system", autonomous_system.into()),
        ("hold_time", hold_time.into()),
        ("identifier", identifier.clone().into()),
        ("four_octet_asn", four.map_or(Json::Null, Json::from)),
        (
            "capabilities",
            Json::array(capabilities.iter().map(|n| (*n).into())),
        ),
        ("extended_optional_parameters", extended_options.into()),
        (
            "field_ranges",
            Json::array([
                field("version", 19, 20),
                field("autonomous_system", 20, 22),
                field("hold_time", 22, 24),
                field("identifier", 24, 28),
                field("optional_length", 28, 29),
            ]),
        ),
        ("parameters", Json::Array(parameters)),
        ("capability_occurrences", Json::Array(occurrences)),
        ("ambiguous", ambiguous.into()),
        ("negotiation_established", false.into()),
    ]);
    let value = Json::object([
        ("source", source),
        ("open", detail),
        ("evidence", evidence),
        ("wire_source_authentication_established", false.into()),
    ]);
    let (encoded, size) = budget.encode(&value, limits.input_bytes.min(limits.retained_bytes))?;
    Ok(OpenState {
        autonomous_system,
        four_octet_asn: four,
        capabilities: capability_set,
        ambiguous,
        capability_issues: issues,
        witness: OpenWitness {
            value,
            encoded_bytes: encoded.len(),
            nodes: size.nodes,
            references: size.references,
        },
    })
}

pub(super) fn repetition(
    ranges: &[AttributeRange],
    code: u8,
    flags: u8,
    digest: &str,
) -> &'static str {
    let mut found = false;
    for previous in ranges.iter().filter(|a| a.code == code) {
        found = true;
        if previous.flags != flags || previous.sha256 != digest {
            return "conflicting";
        }
    }
    if found {
        "duplicate_identical"
    } else {
        "first"
    }
}
fn path_json(path: &[AsPathSegment]) -> Json {
    Json::array(path.iter().map(|s| {
        Json::object([
            ("kind", s.kind.into()),
            ("values", Json::array(s.values.iter().map(|n| (*n).into()))),
        ])
    }))
}
pub(super) fn path_alternatives(
    b: &[u8],
    limits: &Limits,
) -> Result<(Vec<AsPathSegment>, Json, bool)> {
    let mut alternatives = Vec::new();
    let mut paths = Vec::new();
    let mut last_error = None;
    for width in [2usize, 4] {
        match parse_as_path(b, width, limits) {
            Ok(path) => {
                alternatives.push(Json::object([
                    ("asn_width", width.into()),
                    ("as_path", path_json(&path)),
                ]));
                paths.push(path);
            }
            Err(error) if error.code == ErrorCode::LimitExceeded => return Err(error),
            Err(error) => last_error = Some(error),
        }
    }
    if paths.is_empty() {
        return Err(last_error
            .unwrap_or_else(|| bad("bgp_as_path", 0, "no supported width interpretation")));
    }
    let ambiguous = paths.iter().any(|path| path != &paths[0]);
    // A singleton (or identical empty interpretations) supplies a byte-derived
    // value, not a claim that either width was negotiated. Conflicts publish none.
    let path = if ambiguous {
        Vec::new()
    } else {
        paths.remove(0)
    };
    Ok((
        path,
        Json::object([
            ("interpretations", Json::Array(alternatives)),
            ("width_established", false.into()),
        ]),
        ambiguous,
    ))
}
pub(super) fn attribute_value(code: u8, a: &PathAttributes) -> Json {
    match code {
        1 => a.origin.map_or(Json::Null, Json::from),
        2 | 17 => path_json(&a.as_path),
        3 => a.next_hop.clone().map_or(Json::Null, Json::from),
        4 => a.med.map_or(Json::Null, Json::from),
        5 => a.local_preference.map_or(Json::Null, Json::from),
        6 => true.into(),
        7 | 18 => a.aggregator.clone().map_or(Json::Null, Json::from),
        8 => Json::array(a.communities.iter().map(|n| (*n).into())),
        9 => a.originator_id.clone().map_or(Json::Null, Json::from),
        10 => Json::array(a.cluster_list.iter().cloned().map(Json::from)),
        14 => Json::object([
            (
                "next_hop",
                a.next_hop.clone().map_or(Json::Null, Json::from),
            ),
            ("prefixes", Json::array(a.mp_reach.iter().map(Prefix::json))),
        ]),
        15 => Json::array(a.mp_unreach.iter().map(Prefix::json)),
        _ => Json::Null,
    }
}
/// Summaries use the first effective occurrence; later duplicates remain in
/// `attribute_ranges` with their RFC 7606 disposition. Empty list summaries are
/// never an assertion of an empty path.
pub(super) fn merge_attribute(
    a: &mut PathAttributes,
    value: PathAttributes,
    code: u8,
    duplicate: bool,
    codes: &BTreeSet<u8>,
    issues: &mut Vec<&'static str>,
) {
    // RFC 7606 discards later occurrences of ordinary attributes. The first
    // decoded value therefore remains the effective projection; duplicate
    // wire occurrences stay visible in `attribute_ranges`. MP_REACH/UNREACH
    // duplicates are handled as a session reset before this projection is used.
    if duplicate {
        return;
    }
    match code {
        1 => a.origin = value.origin,
        2 => a.as_path = value.as_path,
        3 | 14 => {
            let mixed = codes.contains(&3) && codes.contains(&14);
            a.next_hop = if mixed { None } else { value.next_hop };
            if mixed {
                issues.push("next_hop_family_context_unresolved");
            }
            a.mp_reach.extend(value.mp_reach);
        }
        4 => a.med = value.med,
        5 => a.local_preference = value.local_preference,
        7 => a.aggregator = value.aggregator,
        8 => a.communities = value.communities,
        9 => a.originator_id = value.originator_id,
        10 => a.cluster_list = value.cluster_list,
        15 => a.mp_unreach.extend(value.mp_unreach),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pcap_evidence::provenance::PacketId;

    #[test]
    fn declared_capability_values_keep_typed_ranges_and_invalid_evidence() {
        let (mp, valid, _) = capability_value(1, &[0, 2, 0x7f, 2], 41);
        assert_eq!(valid, Json::from(true));
        assert_eq!(member(&mp, "afi"), Some(&Json::from(2u16)));
        assert_eq!(member(&mp, "reserved"), Some(&Json::from(0x7fu8)));
        let (gr, valid, _) = capability_value(64, &[0x80, 0x3c, 0, 1, 1, 0x80], 50);
        assert_eq!(valid, Json::from(true));
        assert_eq!(
            member(&gr, "restart_time_seconds"),
            Some(&Json::from(60u16))
        );
        let (llgr, valid, _) = capability_value(71, &[0, 1, 1, 0x80, 1, 2, 3], 60);
        assert_eq!(valid, Json::from(true));
        assert_eq!(
            member(&llgr, "kind"),
            Some(&Json::from("long_lived_graceful_restart"))
        );
        let (paths, valid, _) = capability_value(69, &[0, 1, 1, 3], 70);
        assert_eq!(valid, Json::from(true));
        assert_eq!(member(&paths, "kind"), Some(&Json::from("add_path")));
        for (code, bytes, reason) in [
            (1, &[0, 1, 1][..], "invalid_length"),
            (69, &[0, 1, 1, 4][..], "invalid_send_receive"),
            (9, &[5][..], "unassigned_role_value"),
            (65, &[0, 0, 0, 0][..], "as_zero"),
        ] {
            let (decoded, valid, actual_reason) = capability_value(code, bytes, 80);
            assert_eq!(decoded, Json::Null);
            assert_eq!(valid, Json::from(false));
            assert_eq!(actual_reason, reason);
        }
        assert_eq!(capability_value(244, &[1, 2], 80).1, Json::Null);
    }

    #[test]
    fn bilateral_layout_requires_both_open_witnesses_and_directional_modes() {
        let make = |asn, mode| OpenState {
            autonomous_system: 23_456, // AS_TRANS for the four-octet test values.
            four_octet_asn: Some(asn),
            capabilities: CapabilitySet {
                four_octet_asn: Some(asn),
                add_path: BTreeMap::from([((1, 1), mode)]),
                valid: true,
                ..CapabilitySet::default()
            },
            capability_issues: Vec::new(),
            ambiguous: false,
            witness: OpenWitness {
                value: Json::Null,
                encoded_bytes: 0,
                nodes: 0,
                references: 0,
            },
        };
        let mut state = SessionState::default();
        state.opens.insert(0, vec![make(70000, 2)]);
        let (one, basis) = layout_evidence(&state, true);
        assert_eq!(basis, "missing_open_evidence");
        assert_eq!(one.asn_width, 0);
        assert!(one.unresolved_add_path.contains(&(0, 1, 1)));
        assert!(!one.unresolved_add_path.contains(&(0, 2, 1)));
        state.opens.insert(1, vec![make(80000, 1)]);
        let (both, basis) = layout_evidence(&state, true);
        assert_eq!(basis, "both_four_octet_advertisements");
        assert_eq!(both.asn_width, 4);
        assert!(both.add_path.contains(&(0, 1, 1)));
        assert!(!both.add_path.contains(&(1, 1, 1)));
        assert!(both.unresolved_add_path.is_empty());
    }

    #[test]
    fn extended_open_parameter_lengths_are_decoded_by_the_wire_marker() {
        let mut raw = vec![255; 16];
        raw.extend_from_slice(&[
            0, 37, 1, 4, 0, 1, 0, 90, 1, 2, 3, 4, 255, 255, 0, 5, 2, 0, 2, 2, 0,
        ]);
        let bytes = EvidenceBytes::from_packet(
            &raw,
            PacketId {
                capture: [3; 32],
                frame: 1,
                record_offset: 0,
            },
            0,
        );
        let metadata = PcapMetadata {
            source_id: "capture".into(),
            record_id: "open".into(),
            session: Some(1),
            direction: Some(0),
            observed_at_ns: None,
            peer: None,
            local: None,
        };
        let limits = Limits::default();
        let mut budget = Budget::new(&limits);
        let open = parse_open(&bytes, &metadata, &limits, &mut budget).unwrap();
        let detail = member(&open.witness.value, "open").unwrap();
        assert_eq!(
            member(detail, "extended_optional_parameters"),
            Some(&Json::from(true))
        );
        assert_eq!(
            member(detail, "capabilities"),
            Some(&Json::array([Json::from(2u8)]))
        );
    }

    #[test]
    fn generation_overflow_cannot_clear_evidence_or_publish_notification() {
        let mut state = SessionState {
            generation: u64::MAX,
            ..SessionState::default()
        };
        let mut data = vec![255; 16];
        data.extend_from_slice(&[0, 21, 3, 6, 0]);
        let bytes = EvidenceBytes::from_packet(
            &data,
            PacketId {
                capture: [7; 32],
                frame: 1,
                record_offset: 0,
            },
            0,
        );
        let meta = PcapMetadata {
            source_id: "source".into(),
            record_id: "r".into(),
            session: Some(1),
            direction: Some(0),
            observed_at_ns: None,
            peer: None,
            local: None,
        };
        let before = state.clone();
        assert_eq!(
            decode(&bytes, meta, &mut state, &Limits::default())
                .unwrap_err()
                .code,
            ErrorCode::LimitExceeded
        );
        assert_eq!(state, before);
        assert_eq!(state.reset().unwrap_err().code, ErrorCode::LimitExceeded);
        assert_eq!(state, before);
    }

    #[test]
    fn output_node_depth_and_reference_accounting_have_independent_guards() {
        for which in 0..3 {
            let mut limits = Limits::default();
            let value = match which {
                0 => {
                    limits.fields = 2;
                    Json::array([0u8.into(), 1u8.into()])
                }
                1 => {
                    limits.depth = 1;
                    Json::array([0u8.into()])
                }
                _ => {
                    limits.spans = 1;
                    Json::object([("packets", Json::array([0u8.into(), 1u8.into()]))])
                }
            };
            assert_eq!(
                Budget::new(&limits).tree(&value).unwrap_err().code,
                ErrorCode::LimitExceeded
            );
        }
    }
}
