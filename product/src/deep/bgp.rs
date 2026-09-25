//! Bounded BGP route evidence above the framing layer.
//!
//! The normalized record shape is shared by packet-derived observations and
//! caller-supplied imported observations. It deliberately distinguishes source
//! provenance from route interpretation and never claims that a route was
//! installed, selected, or caused an internal flow.
use super::model::{bad, be16, be32, need, Limits};
use pcap_evidence::{json::Json, provenance::EvidenceBytes, sha256, Error, Result};
use std::collections::{BTreeMap, BTreeSet};
use std::net::{Ipv4Addr, Ipv6Addr};

pub(crate) mod mrt;
mod producer;

pub const SCHEMA: &str = "pcap-evidence.bgp.route-evidence.v1";
pub const SEMANTIC_IDENTITY_SCHEMA: &str = "pcap-evidence.bgp.semantic-route-identity.v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceKind {
    Captured,
    Imported,
}
impl SourceKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Captured => "captured",
            Self::Imported => "imported",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RouteAction {
    Announce,
    Withdraw,
}
impl RouteAction {
    fn as_str(self) -> &'static str {
        match self {
            Self::Announce => "announce",
            Self::Withdraw => "withdraw",
        }
    }
}

/// Explicit relationship between this parser's local speaker and its BGP peer.
/// `Unknown` is the compatibility default and is never inferred from packet
/// addresses, transport ports, or the order in which peers appear.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum PeerRelationship {
    #[default]
    Unknown,
    Internal,
    External,
}

impl PeerRelationship {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Internal => "internal",
            Self::External => "external",
        }
    }
}

fn peer_relationship_basis(configured: bool) -> &'static str {
    if configured {
        "explicit_configuration"
    } else {
        "default_unknown"
    }
}

fn effective_update_disposition(
    known_disposition: &'static str,
    peer_relationship_unresolved: bool,
) -> &'static str {
    if known_disposition == "session_reset" {
        known_disposition
    } else if peer_relationship_unresolved {
        "peer_relationship_unresolved"
    } else {
        known_disposition
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Prefix {
    pub afi: u16,
    pub safi: u8,
    pub length: u8,
    pub address: Vec<u8>,
}
impl Prefix {
    pub fn ipv4(address: [u8; 4], length: u8) -> Result<Self> {
        if length > 32 {
            return Err(bad("bgp_prefix", 0, "IPv4 prefix longer than 32"));
        }
        Ok(Self {
            afi: 1,
            safi: 1,
            length,
            address: canonical(address.to_vec(), length),
        })
    }
    pub fn ipv6(address: [u8; 16], length: u8) -> Result<Self> {
        if length > 128 {
            return Err(bad("bgp_prefix", 0, "IPv6 prefix longer than 128"));
        }
        Ok(Self {
            afi: 2,
            safi: 1,
            length,
            address: canonical(address.to_vec(), length),
        })
    }
    fn json(&self) -> Json {
        let address = if self.afi == 1 && self.address.len() == 4 {
            Ipv4Addr::new(
                self.address[0],
                self.address[1],
                self.address[2],
                self.address[3],
            )
            .to_string()
        } else if self.afi == 2 && self.address.len() == 16 {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&self.address);
            Ipv6Addr::from(octets).to_string()
        } else {
            sha256::hex(&self.address)
        };
        Json::object([
            ("afi", self.afi.into()),
            ("safi", self.safi.into()),
            ("length", self.length.into()),
            ("address", address.into()),
        ])
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AsPathSegment {
    pub kind: u8,
    pub values: Vec<u32>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PathAttributes {
    pub origin: Option<u8>,
    pub as_path: Vec<AsPathSegment>,
    pub next_hop: Option<String>,
    pub med: Option<u32>,
    pub local_preference: Option<u32>,
    pub aggregator: Option<String>,
    pub communities: Vec<u32>,
    pub originator_id: Option<String>,
    pub cluster_list: Vec<String>,
    pub mp_reach: Vec<Prefix>,
    pub mp_unreach: Vec<Prefix>,
}

/// Produce a source-neutral, versioned identity for one route candidate.
/// Completeness is derived from the validated effective-attribute inventory
/// and explicit unresolved causes; it is never caller-supplied as a boolean.
/// This fingerprint is never route authority.
pub(crate) struct SemanticIdentityEvidence<'a> {
    pub attributes_present: &'a BTreeSet<u8>,
    pub large_communities: &'a [[u32; 3]],
    pub incompleteness_reasons: &'a BTreeSet<&'static str>,
    pub opaque_occurrences: &'a [Json],
}

pub(crate) fn semantic_route_identity(
    action: RouteAction,
    prefix: &Prefix,
    attributes: &PathAttributes,
    evidence: SemanticIdentityEvidence<'_>,
    limits: &Limits,
) -> Result<Json> {
    let mut reasons = evidence.incompleteness_reasons.clone();
    if action != RouteAction::Announce {
        reasons.insert("route_action_not_announcement");
    }
    if !matches!((prefix.afi, prefix.safi), (1, 1) | (2, 1)) {
        reasons.insert("unsupported_route_family");
    }
    if !evidence.attributes_present.contains(&1) || !evidence.attributes_present.contains(&2) {
        reasons.insert("mandatory_attribute_missing");
    }
    let has_next_hop =
        evidence.attributes_present.contains(&3) ^ evidence.attributes_present.contains(&14);
    if !has_next_hop || attributes.next_hop.is_none() {
        reasons.insert("next_hop_attribute_missing_or_ambiguous");
    }
    let complete = reasons.is_empty();
    let mut opaque = Vec::new();
    opaque
        .try_reserve_exact(evidence.opaque_occurrences.len())
        .map_err(|_| Error::limit("bgp_semantic_identity"))?;
    opaque.extend(evidence.opaque_occurrences.iter().cloned());

    let mut identity_fields = vec![
        ("schema", SEMANTIC_IDENTITY_SCHEMA.into()),
        (
            "completeness",
            if complete {
                "complete"
            } else if reasons.iter().any(|reason| {
                matches!(
                    *reason,
                    "peer_relationship_unresolved"
                        | "asn_width_unresolved"
                        | "add_path_context_unresolved"
                        | "unsupported_route_family"
                        | "next_hop_context_unresolved"
                )
            }) {
                "unresolved"
            } else {
                "incomplete"
            }
            .into(),
        ),
    ];

    if complete {
        let mut communities = attributes.communities.clone();
        communities.sort_unstable();
        communities.dedup();
        let mut large = evidence.large_communities.to_vec();
        large.sort_unstable();
        large.dedup();
        let payload = canonical_semantic_json(&Json::object([
            ("route_key", Json::object([("prefix", prefix.json())])),
            (
                "attributes",
                Json::object([
                    ("origin", attributes.origin.map_or(Json::Null, Json::from)),
                    (
                        "as_path",
                        Json::array(attributes.as_path.iter().map(|segment| {
                            let mut values = segment.values.clone();
                            if matches!(segment.kind, 1 | 4) {
                                values.sort_unstable();
                            }
                            Json::object([
                                ("kind", segment.kind.into()),
                                ("values", Json::array(values.into_iter().map(Json::from))),
                            ])
                        })),
                    ),
                    (
                        "next_hop",
                        attributes.next_hop.clone().map_or(Json::Null, Json::String),
                    ),
                    ("med", attributes.med.map_or(Json::Null, Json::from)),
                    (
                        "local_preference",
                        attributes.local_preference.map_or(Json::Null, Json::from),
                    ),
                    (
                        "aggregator",
                        attributes
                            .aggregator
                            .clone()
                            .map_or(Json::Null, Json::String),
                    ),
                    (
                        "communities",
                        Json::array(communities.into_iter().map(Json::from)),
                    ),
                    (
                        "large_communities",
                        Json::array(
                            large
                                .into_iter()
                                .map(|tuple| Json::array(tuple.into_iter().map(Json::from))),
                        ),
                    ),
                    (
                        "originator_id",
                        attributes
                            .originator_id
                            .clone()
                            .map_or(Json::Null, Json::String),
                    ),
                    (
                        "cluster_list",
                        Json::array(attributes.cluster_list.iter().cloned().map(Json::String)),
                    ),
                ]),
            ),
        ]));
        let encoded = payload.encode_bounded(limits.output_bytes)?;
        let payload_len =
            u64::try_from(encoded.len()).map_err(|_| Error::limit("bgp_semantic_identity"))?;
        let domain = b"pcap-evidence.bgp.semantic-route-identity.v1\0";
        let total = domain
            .len()
            .checked_add(8)
            .and_then(|size| size.checked_add(encoded.len()))
            .ok_or_else(|| Error::limit("bgp_semantic_identity"))?;
        let mut preimage = Vec::new();
        preimage
            .try_reserve_exact(total)
            .map_err(|_| Error::limit("bgp_semantic_identity"))?;
        preimage.extend_from_slice(domain);
        preimage.extend_from_slice(&payload_len.to_be_bytes());
        preimage.extend_from_slice(encoded.as_bytes());
        identity_fields.push((
            "fingerprint_sha256",
            sha256::hex(&sha256::digest(&preimage)).into(),
        ));
        identity_fields.push(("canonical_payload", payload));
    } else {
        identity_fields.push(("fingerprint_sha256", Json::Null));
        identity_fields.push(("canonical_payload", Json::Null));
    }

    identity_fields.push(("opaque_occurrence_fingerprints", Json::Array(opaque)));
    identity_fields.push((
        "incompleteness_reasons",
        Json::array(reasons.into_iter().map(Json::from)),
    ));
    Ok(Json::Object(identity_fields))
}

#[derive(Clone, Debug)]
pub struct ImportedRouteObservation {
    pub source_id: String,
    pub record_id: String,
    pub observed_at_ns: Option<i64>,
    pub session: Option<String>,
    pub peer: Option<String>,
    pub local: Option<String>,
    pub action: RouteAction,
    pub prefix: Prefix,
    pub attributes: PathAttributes,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PcapMetadata {
    pub source_id: String,
    pub record_id: String,
    pub observed_at_ns: Option<i64>,
    pub session: Option<u64>,
    pub direction: Option<u8>,
    pub peer: Option<String>,
    pub local: Option<String>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SessionState {
    generation: u64,
    opens: BTreeMap<u8, Vec<OpenState>>,
    scope: Option<producer::SessionScope>,
    peer_relationship: PeerRelationship,
    peer_relationship_configured: bool,
}
/// A grammar hypothesis supported by one unambiguous OPEN from each direction.
/// It is not a claim that an endpoint accepted or used the capabilities.
#[derive(Clone, Debug, Default)]
pub(super) struct LayoutContext {
    pub asn_width: usize,
    pub peer_relationship: PeerRelationship,
    pub peer_relationship_configured: bool,
    pub add_path: BTreeSet<(u8, u16, u8)>,
    pub unresolved_add_path: BTreeSet<(u8, u16, u8)>,
    pub mp: BTreeSet<(u16, u8)>,
    /// Directions whose opposite-side receiver advertised capability 6.
    pub extended_message_senders: BTreeSet<u8>,
    /// Convenience bilateral summary for existing output consumers.
    pub extended_messages: bool,
    pub enhanced_refresh: bool,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct OpenState {
    pub(super) autonomous_system: u16,
    four_octet_asn: Option<u32>,
    capabilities: producer::CapabilitySet,
    capability_issues: Vec<&'static str>,
    ambiguous: bool,
    witness: producer::OpenWitness,
}

impl SessionState {
    /// Configure RFC 7606 handling for attributes whose disposition depends on
    /// whether this is an internal or external peer. The default is `Unknown`.
    pub fn set_peer_relationship(&mut self, relationship: PeerRelationship) {
        self.peer_relationship = relationship;
        self.peer_relationship_configured = true;
    }

    /// Returns the explicitly configured peer relationship, or `Unknown`.
    pub fn peer_relationship(&self) -> PeerRelationship {
        self.peer_relationship
    }

    pub fn reset(&mut self) -> Result<()> {
        self.generation = self
            .generation
            .checked_add(1)
            .ok_or_else(|| Error::limit("bgp_generation"))?;
        self.opens.clear();
        Ok(())
    }
    /// Caller-visible generation counter, not an inferred endpoint epoch.
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Compatibility helper for the advertised width, NOT negotiated width.
    /// Production parsing uses producer::width_evidence instead.
    fn asn_width(&self, direction: u8) -> usize {
        self.opens
            .get(&direction)
            .filter(|opens| opens.len() == 1)
            .and_then(|opens| opens[0].four_octet_asn)
            .map_or(2, |_| 4)
    }
}

#[derive(Clone, Debug)]
struct PrefixSpan {
    prefix: Prefix,
    start: usize,
    end: usize,
    noncanonical: bool,
    path_id: Option<u32>,
}
#[derive(Clone, Debug)]
struct AttributeRange {
    code: u8,
    flags: u8,
    start: usize,
    end: usize,
    sha256: String,
    value_start: usize,
    value: Json,
    interpretation: &'static str,
    repetition: &'static str,
    validation: Json,
    disposition: &'static str,
    action: Option<UpdateAction>,
    peer_relationship: Option<PeerRelationship>,
    peer_relationship_basis: Option<&'static str>,
    peer_relationship_unresolved: bool,
}
#[derive(Clone, Debug)]
struct RouteRecord {
    action: RouteAction,
    prefix: Prefix,
    start: usize,
    end: usize,
    path_id: Option<u32>,
    attributes: PathAttributes,
    attribute_ranges: Vec<AttributeRange>,
}

pub fn decode_pcap(
    bytes: &EvidenceBytes,
    metadata: PcapMetadata,
    state: &mut SessionState,
    limits: &Limits,
) -> Result<Json> {
    producer::decode(bytes, metadata, state, limits)
}

/// Compatibility entry point: absent import context stays explicitly unknown.
pub fn normalize_imported(input: ImportedRouteObservation, limits: &Limits) -> Result<Json> {
    super::bgp_import::normalize_legacy(input, limits)
}

// Used only after the bounded imported-context preflight; not a public bypass.
pub(crate) fn normalize_imported_raw(
    input: ImportedRouteObservation,
    limits: &Limits,
) -> Result<Json> {
    limits.validate()?;
    if input.source_id.is_empty() || input.record_id.is_empty() {
        return Err(bad(
            "bgp_external_identity",
            0,
            "source and record identity required",
        ));
    }
    let record = RouteRecord {
        action: input.action,
        prefix: input.prefix,
        start: 0,
        end: 0,
        path_id: None,
        attributes: input.attributes,
        attribute_ranges: Vec::new(),
    };
    envelope(
        Source {
            kind: SourceKind::Imported,
            source_id: input.source_id,
            record_id: input.record_id,
            observed_at_ns: input.observed_at_ns,
            session: input.session,
            direction: None,
            peer: input.peer,
            local: input.local,
        },
        0,
        0,
        vec![record],
        vec!["imported_observation_not_wire_verified"],
        EnvelopeDetails {
            message_detail: None,
            evidence: None,
            import_context: None,
        },
        limits,
    )
}

#[derive(Clone, Debug)]
struct Source {
    kind: SourceKind,
    source_id: String,
    record_id: String,
    observed_at_ns: Option<i64>,
    session: Option<String>,
    direction: Option<u8>,
    peer: Option<String>,
    local: Option<String>,
}

struct EnvelopeDetails {
    message_detail: Option<Json>,
    evidence: Option<Json>,
    import_context: Option<Json>,
}

fn envelope(
    source: Source,
    generation: u64,
    message_type: u8,
    records: Vec<RouteRecord>,
    mut issues: Vec<&'static str>,
    details: EnvelopeDetails,
    limits: &Limits,
) -> Result<Json> {
    if records.len() > limits.elements || issues.len() > limits.elements {
        return Err(Error::limit("bgp_route_output"));
    }
    let non_authoritative = [
        "route_candidates_are_not_endpoint_state",
        "cross_source_correlation_requires_explicit_join",
    ];
    issues.extend(non_authoritative);
    let routes = records
        .iter()
        .map(|record| route_json(record, source.kind, limits))
        .collect::<Result<Vec<_>>>()?;
    Ok(Json::object([
        ("schema", SCHEMA.into()),
        ("source_kind", source.kind.as_str().into()),
        ("source_id", source.source_id.into()),
        ("record_id", source.record_id.into()),
        (
            "observed_at_ns",
            source
                .observed_at_ns
                .map_or(Json::Null, |n| n.to_string().into()),
        ),
        ("session", source.session.map_or(Json::Null, Json::String)),
        ("direction", source.direction.map_or(Json::Null, Json::from)),
        ("peer", source.peer.map_or(Json::Null, Json::String)),
        ("local", source.local.map_or(Json::Null, Json::String)),
        ("generation", generation.into()),
        (
            "import_context",
            details.import_context.unwrap_or(Json::Null),
        ),
        ("import_boundary", Json::Null),
        ("message_type", message_type.into()),
        ("routes", Json::Array(routes)),
        (
            "message_detail",
            details.message_detail.unwrap_or(Json::Null),
        ),
        ("issues", Json::array(issues.into_iter().map(Json::from))),
        ("evidence", details.evidence.unwrap_or(Json::Null)),
        ("endpoint_state_established", false.into()),
        ("causality_established", false.into()),
    ]))
}

fn route_json(record: &RouteRecord, source_kind: SourceKind, limits: &Limits) -> Result<Json> {
    let mut value = Json::object([
        ("action", record.action.as_str().into()),
        ("prefix", record.prefix.json()),
        ("field_start", record.start.into()),
        ("field_end", record.end.into()),
        ("attributes", attributes_json(&record.attributes)),
        (
            "attribute_ranges",
            Json::array(record.attribute_ranges.iter().map(attribute_range_json)),
        ),
    ]);
    if source_kind == SourceKind::Captured {
        let Json::Object(fields) = &mut value else {
            return Err(bad(
                "bgp_semantic_identity",
                record.start,
                "normalized route envelope is not an object",
            ));
        };
        fields.push((
            "semantic_identity",
            capture_semantic_identity(record, limits)?,
        ));
    }
    if let (Some(path_id), Json::Object(fields)) = (record.path_id, &mut value) {
        fields.push(("path_id", path_id.into()));
    }
    Ok(value)
}

fn capture_semantic_identity(record: &RouteRecord, limits: &Limits) -> Result<Json> {
    let mut reasons = BTreeSet::new();
    let mut seen = BTreeSet::new();
    let mut large_communities = Vec::new();
    let mut opaque = Vec::new();
    let supported = [1, 2, 3, 4, 5, 7, 8, 9, 10, 14, 15, 32];

    for range in &record.attribute_ranges {
        let is_supported = supported.contains(&range.code);
        let is_later_occurrence = !seen.insert(range.code);
        let discarded_by_duplicate_rule = is_later_occurrence
            && range.disposition == "discard_later_occurrence"
            && !matches!(range.code, 14 | 15);
        let disposition_valid = if is_later_occurrence {
            discarded_by_duplicate_rule
        } else {
            range.disposition == "accept_evidence_only"
        };
        let multiplicity_valid = if is_later_occurrence {
            validation_bool(&range.validation, "multiplicity_valid") == Some(false)
        } else {
            validation_bool(&range.validation, "multiplicity_valid") == Some(true)
        };
        let valid = discarded_by_duplicate_rule
            || (disposition_valid
                && multiplicity_valid
                && (if is_later_occurrence {
                    range.repetition != "first"
                } else {
                    range.repetition == "first"
                })
                && !range.peer_relationship_unresolved
                && validation_bool(&range.validation, "flags_valid") == Some(true)
                && validation_bool(&range.validation, "length_valid") == Some(true)
                && validation_bool(&range.validation, "partial_bit_unexpected") == Some(false)
                && range.flags & 0x20 == 0
                && !matches!(
                    range.interpretation,
                    "unresolved_asn_width" | "unresolved_next_hop_context"
                ));

        if !is_supported {
            reasons.insert("unsupported_path_attribute");
        }
        if is_later_occurrence && !discarded_by_duplicate_rule {
            reasons.insert("duplicate_attribute_unresolved");
        }
        if !valid {
            reasons.insert(if range.peer_relationship_unresolved {
                "peer_relationship_unresolved"
            } else if range.flags & 0x20 != 0 {
                "partial_attribute_value"
            } else if range.interpretation == "unresolved_asn_width" {
                "asn_width_unresolved"
            } else if range.interpretation == "unresolved_next_hop_context" {
                "next_hop_context_unresolved"
            } else {
                "attribute_not_validated_for_semantics"
            });
        }
        if !is_supported || !valid {
            opaque
                .try_reserve(1)
                .map_err(|_| Error::limit("bgp_semantic_identity"))?;
            opaque.push(Json::object([
                ("type", range.code.into()),
                ("flags", range.flags.into()),
                ("value_sha256", range.sha256.clone().into()),
            ]));
        }
        if range.code == 32 && !is_later_occurrence {
            if let Json::Array(values) = &range.value {
                large_communities
                    .try_reserve(values.len())
                    .map_err(|_| Error::limit("bgp_semantic_large_communities"))?;
                for value in values {
                    let Json::Array(tuple) = value else {
                        reasons.insert("large_community_projection_invalid");
                        continue;
                    };
                    if tuple.len() != 3 {
                        reasons.insert("large_community_projection_invalid");
                        continue;
                    }
                    let Some((global, local1, local2)) = tuple
                        .iter()
                        .map(|item| match item {
                            Json::Number(value) => u32::try_from(*value).ok(),
                            _ => None,
                        })
                        .collect::<Option<Vec<_>>>()
                        .and_then(|items| Some((*items.first()?, *items.get(1)?, *items.get(2)?)))
                    else {
                        reasons.insert("large_community_projection_invalid");
                        continue;
                    };
                    large_communities.push([global, local1, local2]);
                }
            } else {
                reasons.insert("large_community_projection_invalid");
            }
        }
    }

    if !seen.contains(&1) || !seen.contains(&2) {
        reasons.insert("mandatory_attribute_missing");
    }
    if seen.contains(&3) == seen.contains(&14) {
        reasons.insert("next_hop_attribute_missing_or_ambiguous");
    }
    semantic_route_identity(
        record.action,
        &record.prefix,
        &record.attributes,
        SemanticIdentityEvidence {
            attributes_present: &seen,
            large_communities: &large_communities,
            incompleteness_reasons: &reasons,
            opaque_occurrences: &opaque,
        },
        limits,
    )
}

fn validation_bool(value: &Json, name: &str) -> Option<bool> {
    let Json::Object(fields) = value else {
        return None;
    };
    fields.iter().find_map(|(key, value)| {
        if *key != name {
            return None;
        }
        match value {
            Json::Bool(value) => Some(*value),
            _ => None,
        }
    })
}

fn canonical_semantic_json(value: &Json) -> Json {
    match value {
        Json::Object(fields) => {
            let mut fields: Vec<_> = fields
                .iter()
                .map(|(key, value)| (*key, canonical_semantic_json(value)))
                .collect();
            fields.sort_by_key(|(key, _)| *key);
            Json::Object(fields)
        }
        Json::Array(values) => Json::array(values.iter().map(canonical_semantic_json)),
        _ => value.clone(),
    }
}

fn attribute_range_json(a: &AttributeRange) -> Json {
    Json::object([
        ("type", a.code.into()),
        ("flags", a.flags.into()),
        ("start", a.start.into()),
        ("end", a.end.into()),
        ("sha256", a.sha256.clone().into()),
        ("value_start", a.value_start.into()),
        ("value_end", a.end.into()),
        ("decoded", a.value.clone()),
        ("interpretation", a.interpretation.into()),
        ("repetition", a.repetition.into()),
        ("validation", a.validation.clone()),
        ("disposition", a.disposition.into()),
        (
            "peer_relationship",
            a.peer_relationship
                .map_or(Json::Null, |relationship| relationship.as_str().into()),
        ),
        (
            "peer_relationship_unresolved",
            a.peer_relationship_unresolved.into(),
        ),
        (
            "peer_relationship_basis",
            a.peer_relationship_basis
                .map_or(Json::Null, |basis| basis.into()),
        ),
    ])
}

fn attributes_json(a: &PathAttributes) -> Json {
    Json::object([
        (
            "origin",
            a.origin.map_or(Json::Null, |n| u64::from(n).into()),
        ),
        (
            "as_path",
            Json::array(a.as_path.iter().map(|s| {
                Json::object([
                    ("kind", s.kind.into()),
                    ("values", Json::array(s.values.iter().map(|n| (*n).into()))),
                ])
            })),
        ),
        (
            "next_hop",
            a.next_hop.clone().map_or(Json::Null, Json::String),
        ),
        ("med", a.med.map_or(Json::Null, |n| n.into())),
        (
            "local_preference",
            a.local_preference.map_or(Json::Null, |n| n.into()),
        ),
        (
            "aggregator",
            a.aggregator.clone().map_or(Json::Null, Json::String),
        ),
        (
            "communities",
            Json::array(a.communities.iter().map(|n| (*n).into())),
        ),
        (
            "originator_id",
            a.originator_id.clone().map_or(Json::Null, Json::String),
        ),
        (
            "cluster_list",
            Json::array(a.cluster_list.iter().cloned().map(Json::String)),
        ),
        ("mp_reach", Json::array(a.mp_reach.iter().map(Prefix::json))),
        (
            "mp_unreach",
            Json::array(a.mp_unreach.iter().map(Prefix::json)),
        ),
    ])
}

fn pcap_evidence(bytes: &EvidenceBytes) -> Json {
    pcap_evidence_stream::events::Evidence::bytes(bytes).json()
}

fn notification_detail(b: &[u8]) -> Json {
    let data_len = u64::try_from(b.len().saturating_sub(21)).map_or(u64::MAX, |n| n);
    Json::object([
        ("code", u64::from(b[19]).into()),
        ("subcode", u64::from(b[20]).into()),
        ("data_len", data_len.into()),
        ("data_sha256", payload_sha256(&b[21..]).into()),
    ])
}

fn route_refresh_detail(b: &[u8]) -> Result<Json> {
    Ok(Json::object([
        ("afi", u64::from(be16(b, 19)?).into()),
        ("reserved", u64::from(b[21]).into()),
        (
            "subtype_kind",
            match b[21] {
                0 => "normal",
                1 => "begin_of_route_refresh",
                2 => "end_of_route_refresh",
                _ => "unknown",
            }
            .into(),
        ),
        ("safi", u64::from(b[22]).into()),
    ]))
}

fn canonical(mut address: Vec<u8>, length: u8) -> Vec<u8> {
    let full = usize::from(length / 8);
    let remainder = length % 8;
    if full < address.len() {
        if remainder != 0 {
            address[full] &= 0xff << (8 - remainder);
        }
        for byte in address.iter_mut().skip(full + usize::from(remainder != 0)) {
            *byte = 0;
        }
    }
    address
}

fn prefix_list(
    b: &[u8],
    mut p: usize,
    end: usize,
    afi: u16,
    safi: u8,
    add_path: bool,
    limits: &Limits,
) -> Result<Vec<PrefixSpan>> {
    let width = match afi {
        1 => 4,
        2 => 16,
        _ => return Err(bad("bgp_afi", p, "unsupported address family")),
    };
    let max_bits = u8::try_from(width * 8).map_err(|_| Error::limit("bgp_prefix"))?;
    let mut out = Vec::new();
    while p < end {
        if out.len() >= limits.elements {
            return Err(Error::limit("bgp_prefixes"));
        }
        let start = p;
        let path_id = if add_path {
            if p.checked_add(4).is_none_or(|n| n > end) {
                return Err(bad("bgp_add_path", p, "path identifier truncated"));
            }
            let id = be32(b, p)?;
            p += 4;
            Some(id)
        } else {
            None
        };
        need(b, p + 1, "bgp_prefix")?;
        let bits = b[p];
        if bits > max_bits {
            return Err(bad("bgp_prefix", p, "prefix length exceeds address family"));
        }
        let octets = usize::from(bits.div_ceil(8));
        p = p
            .checked_add(1)
            .and_then(|n| n.checked_add(octets))
            .ok_or_else(|| Error::limit("bgp_prefix"))?;
        if p > end {
            return Err(bad("bgp_prefix", start, "prefix bytes truncated"));
        }
        let mut address = vec![0u8; width];
        address[..octets].copy_from_slice(&b[start + usize::from(add_path) * 4 + 1..p]);
        let noncanonical = canonical(address.clone(), bits) != address;
        let prefix = Prefix {
            afi,
            safi,
            length: bits,
            address: canonical(address, bits),
        };
        out.push(PrefixSpan {
            prefix,
            start,
            end: p,
            noncanonical,
            path_id,
        });
    }
    Ok(out)
}

struct ParsedUpdate {
    records: Vec<RouteRecord>,
    issues: Vec<&'static str>,
    attribute_ranges: Vec<AttributeRange>,
    disposition: &'static str,
    known_disposition: &'static str,
    peer_relationship: PeerRelationship,
    peer_relationship_basis: &'static str,
    peer_relationship_unresolved: bool,
    end_of_rib: Vec<(u16, u8)>,
    as4_reconstruction: Json,
    opaque_nlri: Vec<Json>,
    missing_mandatory: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum UpdateAction {
    AcceptEvidenceOnly,
    AttributeDiscard,
    TreatAsWithdraw,
    SessionReset,
}

impl UpdateAction {
    fn from_disposition(disposition: &'static str) -> Option<Self> {
        match disposition {
            "accept_evidence_only" => Some(Self::AcceptEvidenceOnly),
            "attribute_discard" => Some(Self::AttributeDiscard),
            "treat_as_withdraw" => Some(Self::TreatAsWithdraw),
            "session_reset" => Some(Self::SessionReset),
            _ => None,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::AcceptEvidenceOnly => "accept_evidence_only",
            Self::AttributeDiscard => "attribute_discard",
            Self::TreatAsWithdraw => "treat_as_withdraw",
            Self::SessionReset => "session_reset",
        }
    }

    fn rank(self) -> u8 {
        match self {
            Self::AcceptEvidenceOnly => 0,
            Self::AttributeDiscard => 1,
            Self::TreatAsWithdraw => 2,
            Self::SessionReset => 3,
        }
    }
}

type AttributeParse = (
    PathAttributes,
    Vec<AttributeRange>,
    Vec<PrefixSpan>,
    Vec<PrefixSpan>,
    Vec<&'static str>,
);

fn attribute_flags(code: u8) -> Option<u8> {
    match code {
        1 | 2 | 3 | 5 | 6 => Some(0x40),
        4 | 9 | 10 | 14 | 15 | 26 => Some(0x80),
        7 | 8 | 16 | 17 | 18 | 32 | 35 => Some(0xc0),
        _ => None,
    }
}

fn attribute_error_disposition(code: u8) -> &'static str {
    match code {
        6 | 7 | 9 | 10 | 17 | 18 | 26 => "attribute_discard",
        14 | 15 => "session_reset",
        _ => "treat_as_withdraw",
    }
}

fn strongest(a: UpdateAction, b: UpdateAction) -> UpdateAction {
    if b.rank() > a.rank() {
        b
    } else {
        a
    }
}

fn path_count(path: &[AsPathSegment]) -> usize {
    path.iter()
        .filter(|s| !matches!(s.kind, 3 | 4))
        .map(|s| {
            if s.kind == 1 {
                usize::from(!s.values.is_empty())
            } else {
                s.values.len()
            }
        })
        .sum()
}

fn as_path_segments_json(path: &[AsPathSegment]) -> Json {
    Json::array(path.iter().map(|segment| {
        Json::object([
            ("kind", segment.kind.into()),
            (
                "values",
                Json::array(segment.values.iter().map(|number| (*number).into())),
            ),
        ])
    }))
}

fn leading_path(path: &[AsPathSegment], mut count: usize) -> Vec<AsPathSegment> {
    let mut leading = Vec::new();
    for segment in path {
        if matches!(segment.kind, 3 | 4) {
            leading.push(segment.clone());
            continue;
        }
        if count == 0 {
            break;
        }
        let take = if segment.kind == 1 {
            segment.values.len()
        } else {
            count.min(segment.values.len())
        };
        if take > 0 {
            leading.push(AsPathSegment {
                kind: segment.kind,
                values: segment.values[..take].to_vec(),
            });
        }
        count = count.saturating_sub(if segment.kind == 1 {
            usize::from(take > 0)
        } else {
            take
        });
    }
    leading
}

fn as4_reconstruction(
    b: &[u8],
    ranges: &[AttributeRange],
    attrs: &mut PathAttributes,
    width: usize,
    limits: &Limits,
) -> Result<Json> {
    let first = |code| {
        ranges
            .iter()
            .find(|r| r.code == code && r.disposition == "accept_evidence_only")
    };
    let (base, as4, agg, as4_agg) = (first(2), first(17), first(7), first(18));
    let any_as4 = ranges.iter().any(|r| matches!(r.code, 17 | 18));
    let mut status = "no_as4_path";
    let mut effective = attrs.as_path.clone();
    let mut effective_aggregator = attrs.aggregator.clone();
    if width == 0 {
        status = "unresolved_layout";
    } else if width == 4 {
        if any_as4 {
            status = "new_new_discard_as4_attributes";
        }
    } else if let Some(base_range) = base {
        let base_path = parse_as_path(&b[base_range.value_start..base_range.end], 2, limits)?;
        effective = base_path.clone();
        let base_agg_asn = agg
            .map(|r| be16(b, r.value_start))
            .transpose()?
            .map(u32::from);
        if let (Some(number), Some(_)) = (base_agg_asn, as4_agg) {
            if number != 23456 {
                status = "non_as_trans_aggregator_discard_as4";
            }
        }
        if status != "non_as_trans_aggregator_discard_as4" {
            if let (Some(number), Some(r)) = (base_agg_asn, as4_agg) {
                if number == 23456 {
                    effective_aggregator = Some(format!(
                        "{}:{}",
                        be32(b, r.value_start)?,
                        Ipv4Addr::from(be32(b, r.value_start + 4)?)
                    ));
                }
            }
            if let Some(as4_range) = as4 {
                let mut four_path =
                    parse_as_path(&b[as4_range.value_start..as4_range.end], 4, limits)?;
                let discarded_confederation = four_path.iter().any(|s| matches!(s.kind, 3 | 4));
                four_path.retain(|s| !matches!(s.kind, 3 | 4));
                if path_count(&four_path) > path_count(&base_path) {
                    status = "longer_as4_path_ignored";
                } else {
                    let lead =
                        leading_path(&base_path, path_count(&base_path) - path_count(&four_path));
                    effective = lead.into_iter().chain(four_path).collect();
                    status = if discarded_confederation {
                        "old_new_reconstructed_confederation_discarded"
                    } else {
                        "old_new_reconstructed"
                    };
                }
            }
        }
    } else if as4.is_some() {
        status = "as4_without_base_path";
    }
    if width != 0 {
        attrs.as_path = effective.clone();
        attrs.aggregator = effective_aggregator.clone();
    }
    Ok(Json::object([
        ("status", status.into()),
        ("effective_as_path", as_path_segments_json(&effective)),
        (
            "effective_aggregator",
            effective_aggregator.map_or(Json::Null, Json::from),
        ),
        (
            "base_as_path_start",
            base.map_or(Json::Null, |r| r.start.into()),
        ),
        ("as4_path_start", as4.map_or(Json::Null, |r| r.start.into())),
        (
            "base_aggregator_start",
            agg.map_or(Json::Null, |r| r.start.into()),
        ),
        (
            "as4_aggregator_start",
            as4_agg.map_or(Json::Null, |r| r.start.into()),
        ),
    ]))
}

fn parse_update(
    b: &[u8],
    context: &LayoutContext,
    direction: Option<u8>,
    limits: &Limits,
    budget: &mut producer::Budget<'_>,
) -> Result<ParsedUpdate> {
    let asn_width = context.asn_width;
    let sender = direction.unwrap_or(2);
    let base_add = context.add_path.contains(&(sender, 1, 1));
    let base_unknown = context.unresolved_add_path.contains(&(sender, 1, 1));
    need(b, 23, "bgp_update")?;
    let withdrawn_len = usize::from(be16(b, 19)?);
    let withdrawn_end = 21usize
        .checked_add(withdrawn_len)
        .ok_or_else(|| Error::limit("bgp_withdrawn"))?;
    need(b, withdrawn_end + 2, "bgp_withdrawn")?;
    let withdrawn = if base_unknown {
        Vec::new()
    } else {
        prefix_list(b, 21, withdrawn_end, 1, 1, base_add, limits)?
    };
    let attribute_len = usize::from(be16(b, withdrawn_end)?);
    let attributes_start = withdrawn_end + 2;
    let attributes_end = attributes_start
        .checked_add(attribute_len)
        .ok_or_else(|| Error::limit("bgp_attributes"))?;
    need(b, attributes_end, "bgp_attributes")?;
    let (mut attributes, mut ranges, mp_withdrawn, mp_announced, mut issues) = parse_attributes(
        b,
        attributes_start,
        attributes_end,
        context,
        sender,
        limits,
        budget,
    )?;
    let as4_reconstruction = as4_reconstruction(b, &ranges, &mut attributes, asn_width, limits)?;
    if let Json::Object(fields) = &as4_reconstruction {
        if let Some((_, Json::String(status))) = fields.iter().find(|(key, _)| *key == "status") {
            for range in &mut ranges {
                if (status == "longer_as4_path_ignored" && range.code == 17)
                    || (status == "non_as_trans_aggregator_discard_as4"
                        && matches!(range.code, 17 | 18))
                {
                    range.disposition = "attribute_discard";
                    range.action = Some(UpdateAction::AttributeDiscard);
                }
            }
        }
    }
    let peer_relationship_unresolved = ranges
        .iter()
        .any(|range| range.peer_relationship_unresolved);
    let mut known_action = UpdateAction::AcceptEvidenceOnly;
    for range in &ranges {
        if let Some(action) = range.action {
            known_action = strongest(known_action, action);
        }
    }
    let mut known_disposition = known_action.as_str();
    let mut disposition =
        effective_update_disposition(known_disposition, peer_relationship_unresolved);
    let announced = if base_unknown {
        Vec::new()
    } else {
        prefix_list(b, attributes_end, b.len(), 1, 1, base_add, limits)?
    };
    let mut end_of_rib = Vec::new();
    if withdrawn_len == 0 && attribute_len == 0 && attributes_end == b.len() {
        end_of_rib.push((1, 1));
    } else if withdrawn_len == 0 && attributes_end == b.len() && ranges.len() == 1 {
        let range = &ranges[0];
        if range.code == 15
            && range.disposition == "accept_evidence_only"
            && range.end.saturating_sub(range.value_start) == 3
        {
            end_of_rib.push((be16(b, range.value_start)?, b[range.value_start + 2]));
        }
    }
    let mut missing_mandatory = Vec::new();
    if !announced.is_empty() || !mp_announced.is_empty() {
        let present: BTreeSet<_> = ranges
            .iter()
            .filter(|r| r.action == Some(UpdateAction::AcceptEvidenceOnly))
            .map(|r| r.code)
            .collect();
        let mandatory = if announced.is_empty() {
            &[1u8, 2][..]
        } else {
            &[1u8, 2, 3][..]
        };
        missing_mandatory = mandatory
            .iter()
            .copied()
            .filter(|c| !present.contains(c))
            .collect();
        if !missing_mandatory.is_empty() {
            known_action = strongest(known_action, UpdateAction::TreatAsWithdraw);
            known_disposition = known_action.as_str();
            disposition =
                effective_update_disposition(known_disposition, peer_relationship_unresolved);
            issues.push("missing_mandatory_attribute");
        }
    }
    let mut opaque_nlri = Vec::new();
    if base_unknown {
        issues.push("add_path_layout_unresolved_opaque_nlri");
        for (start, end, kind) in [
            (21, withdrawn_end, "withdrawn"),
            (attributes_end, b.len(), "announced"),
        ] {
            if start < end {
                opaque_nlri.push(Json::object([
                    ("kind", kind.into()),
                    ("start", start.into()),
                    ("end", end.into()),
                    ("sha256", payload_sha256(&b[start..end]).into()),
                ]));
            }
        }
    }
    let announcement_count = announced
        .len()
        .checked_add(mp_announced.len())
        .ok_or_else(|| Error::limit("bgp_producer_routes"))?;
    let route_count = withdrawn
        .len()
        .checked_add(mp_withdrawn.len())
        .and_then(|n| n.checked_add(announced.len()))
        .and_then(|n| n.checked_add(mp_announced.len()))
        .ok_or_else(|| Error::limit("bgp_producer_routes"))?;
    budget.routes(route_count, &attributes, &ranges)?;
    let mut records = Vec::new();
    for item in withdrawn {
        records.push(RouteRecord {
            action: RouteAction::Withdraw,
            prefix: item.prefix,
            start: item.start,
            end: item.end,
            path_id: item.path_id,
            attributes: PathAttributes::default(),
            attribute_ranges: Vec::new(),
        });
        if item.noncanonical {
            issues.push("noncanonical_prefix_bits_masked");
        }
    }
    for item in mp_withdrawn {
        records.push(RouteRecord {
            action: RouteAction::Withdraw,
            prefix: item.prefix,
            start: item.start,
            end: item.end,
            path_id: item.path_id,
            attributes: attributes.clone(),
            attribute_ranges: ranges.clone(),
        });
        if item.noncanonical {
            issues.push("noncanonical_prefix_bits_masked");
        }
    }
    for item in announced.into_iter().chain(mp_announced) {
        records.push(RouteRecord {
            action: RouteAction::Announce,
            prefix: item.prefix,
            start: item.start,
            end: item.end,
            path_id: item.path_id,
            attributes: attributes.clone(),
            attribute_ranges: ranges.clone(),
        });
        if item.noncanonical {
            issues.push("noncanonical_prefix_bits_masked");
        }
    }
    if known_action == UpdateAction::TreatAsWithdraw && announcement_count == 0 {
        known_action = UpdateAction::SessionReset;
        known_disposition = known_action.as_str();
        disposition = effective_update_disposition(known_disposition, peer_relationship_unresolved);
        issues.push("route_free_malformed_update_requires_session_reset");
    }
    match known_action {
        UpdateAction::TreatAsWithdraw => {
            for record in &mut records {
                if record.action == RouteAction::Announce {
                    record.action = RouteAction::Withdraw;
                }
            }
            issues.push("treat_as_withdraw_applied_to_route_actions");
        }
        UpdateAction::SessionReset => {
            for record in &records {
                let mut fields = vec![
                    ("kind", "session_reset_route".into()),
                    ("action", record.action.as_str().into()),
                    ("start", record.start.into()),
                    ("end", record.end.into()),
                    (
                        "sha256",
                        payload_sha256(&b[record.start..record.end]).into(),
                    ),
                    ("prefix", record.prefix.json()),
                ];
                if let Some(path_id) = record.path_id {
                    fields.push(("path_id", path_id.into()));
                }
                opaque_nlri.push(Json::Object(fields));
            }
            records.clear();
            issues.push("session_reset_suppressed_route_actions");
        }
        UpdateAction::AcceptEvidenceOnly | UpdateAction::AttributeDiscard => {}
    }
    if peer_relationship_unresolved {
        for record in &records {
            let mut fields = vec![
                ("kind", "peer_relationship_unresolved_route".into()),
                ("action", record.action.as_str().into()),
                ("start", record.start.into()),
                ("end", record.end.into()),
                (
                    "sha256",
                    payload_sha256(&b[record.start..record.end]).into(),
                ),
                ("prefix", record.prefix.json()),
            ];
            if let Some(path_id) = record.path_id {
                fields.push(("path_id", path_id.into()));
            }
            opaque_nlri.push(Json::Object(fields));
        }
        records.clear();
        issues.push("peer_relationship_context_unresolved_route_actions_quarantined");
    }
    if asn_width == 2 {
        issues.push("asn_width_derived_from_two_octet_default_or_open");
    }
    Ok(ParsedUpdate {
        records,
        issues,
        attribute_ranges: ranges,
        disposition,
        known_disposition,
        peer_relationship: context.peer_relationship,
        peer_relationship_basis: peer_relationship_basis(context.peer_relationship_configured),
        peer_relationship_unresolved,
        end_of_rib,
        as4_reconstruction,
        opaque_nlri,
        missing_mandatory,
    })
}

fn parse_attributes(
    b: &[u8],
    mut p: usize,
    end: usize,
    context: &LayoutContext,
    sender: u8,
    limits: &Limits,
    budget: &mut producer::Budget<'_>,
) -> Result<AttributeParse> {
    let asn_width = context.asn_width;
    let mut attrs = PathAttributes::default();
    let mut ranges = Vec::new();
    let mut mp_withdrawn = Vec::new();
    let mut mp_announced = Vec::new();
    let mut issues = Vec::new();
    let mut seen_codes = BTreeSet::new();
    while p < end {
        if ranges.len() >= limits.elements {
            return Err(Error::limit("bgp_attributes"));
        }
        let start = p;
        if p.checked_add(3).is_none_or(|n| n > end) {
            return Err(bad(
                "bgp_attribute_header",
                p,
                "header exceeds attribute block",
            ));
        }
        need(b, p + 3, "bgp_attribute_header")?;
        let flags = b[p];
        let code = b[p + 1];
        let extended = flags & 0x10 != 0;
        let header = if extended { 4 } else { 3 };
        if p.checked_add(header).is_none_or(|n| n > end) {
            return Err(bad(
                "bgp_attribute_header",
                p,
                "extended header exceeds attribute block",
            ));
        }
        need(b, p + header, "bgp_attribute_header")?;
        let length = if extended {
            usize::from(be16(b, p + 2)?)
        } else {
            usize::from(b[p + 2])
        };
        let value_start = p + header;
        let value_end = value_start
            .checked_add(length)
            .ok_or_else(|| Error::limit("bgp_attribute"))?;
        if value_end > end {
            return Err(bad("bgp_attribute", start, "attribute exceeds UPDATE"));
        }
        budget.charge(
            ranges
                .len()
                .saturating_mul(70)
                .saturating_add(length.saturating_mul(16))
                .saturating_add(256),
        )?;
        let duplicate = !seen_codes.insert(code);
        if duplicate {
            issues.push("duplicate_path_attribute_type");
        }
        let digest = payload_sha256(&b[value_start..value_end]);
        let repetition = producer::repetition(&ranges, code, flags, &digest);
        if repetition == "conflicting" {
            issues.push("conflicting_path_attribute_values");
        }
        let mut item = PathAttributes::default();
        let mut special = None;
        let mut interpretation = if matches!(code, 1..=10 | 14 | 15 | 16 | 17 | 18 | 26 | 32 | 35) {
            "decoded_subset"
        } else {
            "unsupported"
        };
        let parsed: Result<()> = (|| {
            match code {
                1 => {
                    if length != 1 || b[value_start] > 2 {
                        return Err(bad("bgp_origin", value_start, "invalid ORIGIN value"));
                    }
                    item.origin = Some(b[value_start]);
                }
                2 => {
                    if asn_width == 0 {
                        let (path, alternatives, ambiguous) =
                            producer::path_alternatives(&b[value_start..value_end], limits)?;
                        item.as_path = path;
                        special = Some(alternatives);
                        interpretation = if ambiguous {
                            "unresolved_asn_width"
                        } else {
                            "wire_shape_only_not_negotiated"
                        };
                        if ambiguous {
                            issues.push("asn_width_unresolved_no_negotiated_authority");
                        } else {
                            issues.push("asn_width_derived_from_two_octet_default_or_open");
                        }
                    } else {
                        item.as_path =
                            parse_as_path(&b[value_start..value_end], asn_width, limits)?;
                    }
                    if item
                        .as_path
                        .iter()
                        .any(|segment| segment.values.contains(&0))
                    {
                        return Err(bad("bgp_as_zero", value_start, "AS_PATH contains AS 0"));
                    }
                }
                3 => {
                    if length != 4 {
                        return Err(bad("bgp_next_hop", value_start, "NEXT_HOP must be IPv4"));
                    }
                    item.next_hop = Some(
                        Ipv4Addr::new(
                            b[value_start],
                            b[value_start + 1],
                            b[value_start + 2],
                            b[value_start + 3],
                        )
                        .to_string(),
                    );
                }
                4 => {
                    if length != 4 {
                        return Err(bad("bgp_med", value_start, "MED must be four octets"));
                    }
                    item.med = Some(be32(b, value_start)?);
                }
                5 => {
                    if length != 4 {
                        return Err(bad(
                            "bgp_local_preference",
                            value_start,
                            "LOCAL_PREF must be four octets",
                        ));
                    }
                    item.local_preference = Some(be32(b, value_start)?);
                }
                6 => {
                    if length != 0 {
                        return Err(bad(
                            "bgp_atomic_aggregate",
                            value_start,
                            "ATOMIC_AGGREGATE has no value",
                        ));
                    }
                }
                7 => {
                    let width = if asn_width == 0 {
                        interpretation = "wire_shape_only_not_negotiated";
                        match length {
                            6 => 2,
                            8 => 4,
                            _ => 0,
                        }
                    } else {
                        asn_width
                    };
                    if width == 0 || length != width + 4 {
                        return Err(bad(
                            "bgp_aggregator",
                            value_start,
                            "AGGREGATOR width disagrees with bounded context",
                        ));
                    }
                    let number = if width == 2 {
                        u32::from(be16(b, value_start)?)
                    } else {
                        be32(b, value_start)?
                    };
                    if number == 0 {
                        return Err(bad("bgp_as_zero", value_start, "AGGREGATOR contains AS 0"));
                    }
                    let value = format!(
                        "{}:{}",
                        number,
                        Ipv4Addr::from(be32(b, value_start + width)?)
                    );
                    item.aggregator = Some(value);
                }
                8 => {
                    if length == 0 || length % 4 != 0 {
                        return Err(bad(
                            "bgp_communities",
                            value_start,
                            "COMMUNITIES width must be a nonzero multiple of four",
                        ));
                    }
                    if length / 4 > limits.elements {
                        return Err(Error::limit("bgp_attribute_values"));
                    }
                    for q in (value_start..value_end).step_by(4) {
                        item.communities.push(be32(b, q)?);
                    }
                }
                9 => {
                    if length != 4 {
                        return Err(bad(
                            "bgp_originator_id",
                            value_start,
                            "ORIGINATOR_ID must be four octets",
                        ));
                    }
                    item.originator_id = Some(Ipv4Addr::from(be32(b, value_start)?).to_string());
                }
                10 => {
                    if length == 0 || length % 4 != 0 {
                        return Err(bad(
                            "bgp_cluster_list",
                            value_start,
                            "CLUSTER_LIST width must be a nonzero multiple of four",
                        ));
                    }
                    if length / 4 > limits.elements {
                        return Err(Error::limit("bgp_attribute_values"));
                    }
                    for q in (value_start..value_end).step_by(4) {
                        item.cluster_list
                            .push(Ipv4Addr::from(be32(b, q)?).to_string());
                    }
                }
                14 => {
                    if length < 3 {
                        return Err(bad("bgp_mp_reach", value_start, "family header truncated"));
                    }
                    let family = (be16(b, value_start)?, b[value_start + 2]);
                    if !matches!(family, (1 | 2, 1 | 2))
                        || !context.mp.contains(&family)
                        || context
                            .unresolved_add_path
                            .contains(&(sender, family.0, family.1))
                    {
                        interpretation = "opaque_family_capability_or_add_path_layout";
                        special = Some(Json::object([
                            ("afi", family.0.into()),
                            ("safi", family.1.into()),
                            ("sha256", digest.clone().into()),
                        ]));
                        issues.push(if !context.mp.contains(&family) {
                            "mp_reach_capability_unresolved"
                        } else {
                            "mp_reach_opaque_nlri"
                        });
                    } else {
                        if length >= 4 {
                            let reserved_at = value_start + 4 + usize::from(b[value_start + 3]);
                            if reserved_at < value_end && b[reserved_at] != 0 {
                                issues.push("mp_reach_reserved_nonzero_ignored");
                            }
                        }
                        let (next_hop, prefixes) = parse_mp_reach(
                            b,
                            value_start,
                            value_end,
                            context.add_path.contains(&(sender, family.0, family.1)),
                            limits,
                        )?;
                        item.next_hop = Some(next_hop);
                        item.mp_reach
                            .extend(prefixes.iter().map(|p| p.prefix.clone()));
                        mp_announced.extend(prefixes);
                    }
                }
                15 => {
                    if length < 3 {
                        return Err(bad(
                            "bgp_mp_unreach",
                            value_start,
                            "family header truncated",
                        ));
                    }
                    let family = (be16(b, value_start)?, b[value_start + 2]);
                    if !matches!(family, (1 | 2, 1 | 2))
                        || !context.mp.contains(&family)
                        || context
                            .unresolved_add_path
                            .contains(&(sender, family.0, family.1))
                    {
                        interpretation = "opaque_family_capability_or_add_path_layout";
                        special = Some(Json::object([
                            ("afi", family.0.into()),
                            ("safi", family.1.into()),
                            ("sha256", digest.clone().into()),
                        ]));
                        issues.push(if !context.mp.contains(&family) {
                            "mp_unreach_capability_unresolved"
                        } else {
                            "mp_unreach_opaque_nlri"
                        });
                    } else {
                        let prefixes = parse_mp_unreach(
                            b,
                            value_start,
                            value_end,
                            context.add_path.contains(&(sender, family.0, family.1)),
                            limits,
                        )?;
                        item.mp_unreach
                            .extend(prefixes.iter().map(|p| p.prefix.clone()));
                        mp_withdrawn.extend(prefixes);
                    }
                }
                17 => {
                    if length < 6 {
                        return Err(bad(
                            "bgp_as4_path",
                            value_start,
                            "AS4_PATH must contain a complete nonempty segment",
                        ));
                    }
                    item.as_path = parse_as_path(&b[value_start..value_end], 4, limits)?;
                    if item
                        .as_path
                        .iter()
                        .any(|segment| segment.values.contains(&0))
                    {
                        return Err(bad("bgp_as_zero", value_start, "AS4_PATH contains AS 0"));
                    }
                    let raw_segments = item.as_path.clone();
                    if item
                        .as_path
                        .iter()
                        .any(|segment| matches!(segment.kind, 3 | 4))
                    {
                        item.as_path
                            .retain(|segment| !matches!(segment.kind, 3 | 4));
                        issues.push("as4_confederation_segments_discarded");
                    }
                    special = Some(Json::object([
                        ("raw_segments", as_path_segments_json(&raw_segments)),
                        ("usable_segments", as_path_segments_json(&item.as_path)),
                    ]));
                }
                18 => {
                    if length != 8 {
                        return Err(bad(
                            "bgp_as4_aggregator",
                            value_start,
                            "AS4_AGGREGATOR must be eight octets",
                        ));
                    }
                    if be32(b, value_start)? == 0 {
                        return Err(bad(
                            "bgp_as_zero",
                            value_start,
                            "AS4_AGGREGATOR contains AS 0",
                        ));
                    }
                    item.aggregator = Some(format!(
                        "{}:{}",
                        be32(b, value_start)?,
                        Ipv4Addr::from(be32(b, value_start + 4)?)
                    ));
                }
                16 => {
                    if length == 0 || length % 8 != 0 {
                        return Err(bad(
                            "bgp_extended_communities",
                            value_start,
                            "value length must be a nonzero multiple of eight",
                        ));
                    }
                    special = Some(Json::array(
                        b[value_start..value_end].chunks_exact(8).enumerate().map(
                            |(index, chunk)| {
                                Json::object([
                                    ("type", chunk[0].into()),
                                    ("subtype", chunk[1].into()),
                                    ("value_sha256", payload_sha256(&chunk[2..]).into()),
                                    ("start", (value_start + index * 8).into()),
                                    ("end", (value_start + (index + 1) * 8).into()),
                                ])
                            },
                        ),
                    ));
                }
                26 => {
                    if length == 0 {
                        return Err(bad(
                            "bgp_aigp",
                            value_start,
                            "AIGP must contain at least one TLV",
                        ));
                    }
                    let mut q = value_start;
                    let mut tuples = Vec::new();
                    while q < value_end {
                        if q + 3 > value_end {
                            return Err(bad("bgp_aigp", q, "TLV header truncated"));
                        }
                        let tlv_len = usize::from(be16(b, q + 1)?);
                        if tlv_len < 3 || q + tlv_len > value_end {
                            return Err(bad("bgp_aigp", q, "TLV length invalid"));
                        }
                        if b[q] == 1 && tlv_len != 11 {
                            return Err(bad("bgp_aigp", q, "AIGP metric length invalid"));
                        }
                        tuples.push(Json::object([
                            ("type", b[q].into()),
                            ("length", tlv_len.into()),
                            (
                                "metric",
                                if b[q] == 1 {
                                    u64::from_be_bytes(
                                        b[q + 3..q + 11]
                                            .try_into()
                                            .map_err(|_| bad("bgp_aigp", q, "metric truncated"))?,
                                    )
                                    .into()
                                } else {
                                    Json::Null
                                },
                            ),
                            ("sha256", payload_sha256(&b[q..q + tlv_len]).into()),
                        ]));
                        q += tlv_len;
                    }
                    special = Some(Json::Array(tuples));
                }
                32 => {
                    if length == 0 || length % 12 != 0 {
                        return Err(bad(
                            "bgp_large_community",
                            value_start,
                            "value length must be a nonzero multiple of twelve",
                        ));
                    }
                    special = Some(Json::array((value_start..value_end).step_by(12).map(|q| {
                        Json::array([
                            be32(b, q).unwrap_or(0).into(),
                            be32(b, q + 4).unwrap_or(0).into(),
                            be32(b, q + 8).unwrap_or(0).into(),
                        ])
                    })));
                }
                35 => {
                    if length != 4 {
                        return Err(bad("bgp_otc", value_start, "OTC must contain four octets"));
                    }
                    special = Some(be32(b, value_start)?.into());
                }
                _ => issues.push("unknown_or_invalid_path_attribute_retained_by_hash"),
            }
            Ok(())
        })();
        let value_valid = match parsed {
            Ok(()) => true,
            Err(error) if error.code == pcap_evidence::ErrorCode::LimitExceeded => {
                return Err(error)
            }
            Err(_) => {
                issues.push("malformed_path_attribute_retained");
                item = PathAttributes::default();
                special = None;
                interpretation = "invalid_retained_by_hash";
                false
            }
        };
        if matches!(code, 3 | 14) && seen_codes.contains(&3) && seen_codes.contains(&14) {
            interpretation = "unresolved_next_hop_context";
        }
        let expected_flags = attribute_flags(code);
        let flags_valid = expected_flags.is_none_or(|expected| flags & 0xc0 == expected);
        let reserved_bits_nonzero = flags & 0x0f != 0;
        let partial_bit_unexpected = flags & 0x20 != 0 && flags & 0xc0 != 0xc0;
        if !flags_valid {
            issues.push("attribute_flags_invalid");
        }
        if reserved_bits_nonzero || partial_bit_unexpected {
            issues.push("attribute_flag_anomaly_retained");
        }
        let peer_dependent = matches!(code, 5 | 9 | 10);
        let peer_relationship = peer_dependent.then_some(context.peer_relationship);
        let relationship_basis = peer_dependent.then_some(peer_relationship_basis(
            context.peer_relationship_configured,
        ));
        let peer_relationship_unresolved =
            peer_dependent && context.peer_relationship == PeerRelationship::Unknown;
        let disposition = if duplicate {
            if matches!(code, 14 | 15) {
                "session_reset"
            } else {
                "discard_later_occurrence"
            }
        } else if asn_width == 4 && matches!(code, 17 | 18) {
            "attribute_discard"
        } else if peer_dependent && !flags_valid {
            "treat_as_withdraw"
        } else if peer_dependent {
            match context.peer_relationship {
                PeerRelationship::Unknown => "peer_relationship_unresolved",
                PeerRelationship::External => "attribute_discard",
                PeerRelationship::Internal if !value_valid => "treat_as_withdraw",
                PeerRelationship::Internal => "accept_evidence_only",
            }
        } else if !value_valid {
            attribute_error_disposition(code)
        } else if !flags_valid {
            "treat_as_withdraw"
        } else if expected_flags.is_none() && flags & 0x80 == 0 {
            "session_reset"
        } else if expected_flags.is_none() && flags & 0x40 == 0 {
            "attribute_discard"
        } else {
            "accept_evidence_only"
        };
        if peer_dependent
            && context.peer_relationship == PeerRelationship::External
            && value_valid
            && flags_valid
        {
            interpretation = "decoded_but_discarded_for_external_peer";
        } else if peer_dependent
            && context.peer_relationship == PeerRelationship::Unknown
            && value_valid
            && flags_valid
        {
            interpretation = "decoded_but_unresolved_peer_relationship";
        }
        let validation = Json::object([
            ("known", expected_flags.is_some().into()),
            (
                "expected_flags",
                expected_flags.map_or(Json::Null, Json::from),
            ),
            ("flags_valid", flags_valid.into()),
            ("reserved_bits_nonzero", reserved_bits_nonzero.into()),
            ("partial_bit_unexpected", partial_bit_unexpected.into()),
            ("length_valid", value_valid.into()),
            ("multiplicity_valid", (!duplicate).into()),
        ]);
        let value = if value_valid {
            special.unwrap_or_else(|| producer::attribute_value(code, &item))
        } else {
            Json::Null
        };
        ranges.push(AttributeRange {
            code,
            flags,
            start,
            end: value_end,
            sha256: digest,
            value_start,
            value,
            interpretation,
            repetition,
            validation,
            disposition,
            action: UpdateAction::from_disposition(disposition),
            peer_relationship,
            peer_relationship_basis: relationship_basis,
            peer_relationship_unresolved,
        });
        if value_valid
            && flags_valid
            && (!peer_dependent || context.peer_relationship == PeerRelationship::Internal)
        {
            producer::merge_attribute(&mut attrs, item, code, duplicate, &seen_codes, &mut issues);
        }
        p = value_end;
    }
    Ok((attrs, ranges, mp_withdrawn, mp_announced, issues))
}

fn parse_as_path(b: &[u8], width: usize, limits: &Limits) -> Result<Vec<AsPathSegment>> {
    if !matches!(width, 2 | 4) {
        return Err(Error::limit("bgp_asn_width"));
    }
    let mut p = 0;
    let mut out = Vec::new();
    let mut total_values = 0usize;
    while p < b.len() {
        if out.len() >= limits.elements {
            return Err(Error::limit("bgp_as_path"));
        }
        need(b, p + 2, "bgp_as_path_segment")?;
        let kind = b[p];
        let count = usize::from(b[p + 1]);
        if count == 0 {
            return Err(bad(
                "bgp_as_path_segment",
                p + 1,
                "zero-length AS_PATH segment",
            ));
        }
        if !matches!(kind, 1..=4) {
            return Err(bad(
                "bgp_as_path_segment",
                p,
                "unknown AS_PATH segment type",
            ));
        }
        let bytes = count
            .checked_mul(width)
            .ok_or_else(|| Error::limit("bgp_as_path"))?;
        let end = p
            .checked_add(2)
            .and_then(|n| n.checked_add(bytes))
            .ok_or_else(|| Error::limit("bgp_as_path"))?;
        if end > b.len() {
            return Err(bad("bgp_as_path_segment", p, "AS_PATH segment truncated"));
        }
        total_values = total_values
            .checked_add(count)
            .ok_or_else(|| Error::limit("bgp_as_path_values"))?;
        if total_values > limits.elements {
            return Err(Error::limit("bgp_as_path_values"));
        }
        let mut values = Vec::with_capacity(count);
        for q in 0..count {
            let at = p + 2 + q * width;
            values.push(if width == 2 {
                u32::from(be16(b, at)?)
            } else {
                be32(b, at)?
            });
        }
        out.push(AsPathSegment { kind, values });
        p = end;
    }
    Ok(out)
}

fn parse_mp_reach(
    b: &[u8],
    start: usize,
    end: usize,
    add_path: bool,
    limits: &Limits,
) -> Result<(String, Vec<PrefixSpan>)> {
    let header_end = start
        .checked_add(4)
        .ok_or_else(|| Error::limit("bgp_mp_reach"))?;
    if header_end > end {
        return Err(bad("bgp_mp_reach", start, "header exceeds attribute"));
    }
    let afi = be16(b, start)?;
    let safi = b[start + 2];
    let next_hop_len = usize::from(b[start + 3]);
    let next_hop_end = header_end
        .checked_add(next_hop_len)
        .ok_or_else(|| Error::limit("bgp_mp_reach"))?;
    if next_hop_end >= end {
        return Err(bad(
            "bgp_mp_reach",
            start,
            "next hop and SNPA count exceed attribute",
        ));
    }
    // RFC 4760 renamed this octet Reserved and requires receivers to ignore it.
    let prefixes = prefix_list(b, next_hop_end + 1, end, afi, safi, add_path, limits)?;
    let expected_next_hop = match afi {
        1 => 4,
        2 if next_hop_len == 16 || next_hop_len == 32 => next_hop_len,
        2 => {
            return Err(bad(
                "bgp_mp_reach",
                start + 3,
                "invalid IPv6 next-hop length",
            ))
        }
        _ => return Err(bad("bgp_afi", start, "unsupported address family")),
    };
    if next_hop_len != expected_next_hop {
        return Err(bad("bgp_mp_reach", start + 3, "invalid next-hop length"));
    }
    let next_hop = if afi == 1 && next_hop_len >= 4 {
        Ipv4Addr::new(b[start + 4], b[start + 5], b[start + 6], b[start + 7]).to_string()
    } else if afi == 2 && next_hop_len == 16 {
        let mut octets = [0u8; 16];
        octets.copy_from_slice(&b[start + 4..start + 20]);
        Ipv6Addr::from(octets).to_string()
    } else if afi == 2 && next_hop_len == 32 {
        let mut global = [0u8; 16];
        let mut link_local = [0u8; 16];
        global.copy_from_slice(&b[start + 4..start + 20]);
        link_local.copy_from_slice(&b[start + 20..start + 36]);
        format!("{},{}", Ipv6Addr::from(global), Ipv6Addr::from(link_local))
    } else {
        payload_sha256(&b[start + 4..next_hop_end])
    };
    Ok((next_hop, prefixes))
}

fn parse_mp_unreach(
    b: &[u8],
    start: usize,
    end: usize,
    add_path: bool,
    limits: &Limits,
) -> Result<Vec<PrefixSpan>> {
    let header_end = start
        .checked_add(3)
        .ok_or_else(|| Error::limit("bgp_mp_unreach"))?;
    if header_end > end {
        return Err(bad("bgp_mp_unreach", start, "header exceeds attribute"));
    }
    prefix_list(
        b,
        start + 3,
        end,
        be16(b, start)?,
        b[start + 2],
        add_path,
        limits,
    )
}

fn payload_sha256(data: &[u8]) -> String {
    sha256::hex(&sha256::digest(data))
}

#[cfg(test)]
mod tests {
    use super::*;
    use pcap_evidence::{
        provenance::{EvidenceBytes, PacketId},
        sha256,
    };

    fn evidence(bytes: &[u8]) -> EvidenceBytes {
        EvidenceBytes::from_packet(
            bytes,
            PacketId {
                capture: sha256::digest(b"bgp-tests"),
                frame: 1,
                record_offset: 0,
            },
            0,
        )
    }
    fn meta() -> PcapMetadata {
        PcapMetadata {
            source_id: "capture-test".into(),
            record_id: "record-1".into(),
            observed_at_ns: Some(42),
            session: Some(7),
            direction: Some(0),
            peer: Some("198.51.100.2".into()),
            local: Some("198.51.100.1".into()),
        }
    }
    fn update() -> Vec<u8> {
        let mut b = vec![0xff; 16];
        b.extend_from_slice(&[0, 0, 2]);
        let body = vec![
            0, 2, 8, 10, 0, 18, 0x40, 1, 1, 0, 0x40, 2, 4, 2, 1, 0, 100, 0x40, 3, 4, 192, 0, 2, 1,
            24, 203, 0, 113,
        ];
        b.extend_from_slice(&body);
        let length = u16::try_from(b.len()).unwrap();
        b[16..18].copy_from_slice(&length.to_be_bytes());
        b
    }

    fn complete_range(code: u8, flags: u8) -> AttributeRange {
        AttributeRange {
            code,
            flags,
            start: 0,
            end: 3,
            sha256: "00".repeat(32),
            value_start: 2,
            value: Json::Null,
            interpretation: "decoded",
            repetition: "first",
            validation: Json::object([
                ("flags_valid", true.into()),
                ("length_valid", true.into()),
                ("multiplicity_valid", true.into()),
                ("reserved_bits_nonzero", false.into()),
                ("partial_bit_unexpected", false.into()),
            ]),
            disposition: "accept_evidence_only",
            action: None,
            peer_relationship: None,
            peer_relationship_basis: None,
            peer_relationship_unresolved: false,
        }
    }

    #[test]
    fn add_path_identifier_is_a_state_key_not_cross_source_semantics() {
        let prefix = Prefix::ipv4([203, 0, 113, 0], 24).unwrap();
        let attributes = PathAttributes {
            origin: Some(0),
            as_path: vec![AsPathSegment {
                kind: 2,
                values: vec![64_512],
            }],
            next_hop: Some("192.0.2.1".into()),
            ..PathAttributes::default()
        };
        let mut record = RouteRecord {
            action: RouteAction::Announce,
            prefix,
            start: 19,
            end: 23,
            path_id: Some(7),
            attributes,
            attribute_ranges: vec![
                complete_range(1, 0x40),
                complete_range(2, 0x40),
                complete_range(3, 0x40),
            ],
        };
        let first = route_json(&record, SourceKind::Captured, &Limits::default()).unwrap();
        record.path_id = Some(99);
        let second = route_json(&record, SourceKind::Captured, &Limits::default()).unwrap();
        fn field<'a>(value: &'a Json, name: &str) -> &'a Json {
            let Json::Object(fields) = value else {
                panic!("expected route object")
            };
            fields
                .iter()
                .find(|(key, _)| *key == name)
                .map(|(_, value)| value)
                .unwrap()
        }
        assert_eq!(field(&first, "path_id"), &Json::from(7u32));
        assert_eq!(field(&second, "path_id"), &Json::from(99u32));
        assert_eq!(
            field(field(&first, "semantic_identity"), "fingerprint_sha256"),
            field(field(&second, "semantic_identity"), "fingerprint_sha256")
        );
    }

    #[test]
    fn update_normalizes_announcements_withdrawals_and_attributes() {
        let mut state = SessionState::default();
        let output = decode_pcap(&evidence(&update()), meta(), &mut state, &Limits::default())
            .unwrap()
            .encode();
        assert!(output.contains("pcap-evidence.bgp.route-evidence.v1"));
        assert!(output.contains("\"action\":\"withdraw\""));
        assert!(output.contains("\"action\":\"announce\""));
        assert!(output.contains("203.0.113.0"));
        assert!(output.contains("\"as_path\""));
        assert!(output.contains("route_candidates_are_not_endpoint_state"));
    }

    #[test]
    fn open_capability_selects_four_octet_asn_width_for_the_direction() {
        let mut b = vec![0xff; 16];
        b.extend_from_slice(&[0, 37, 1, 4, 0xfd, 0xe8, 0, 90]);
        b.extend_from_slice(&[192, 0, 2, 2, 8, 2, 6, 65, 4, 0, 1, 0, 100]);
        let mut state = SessionState::default();
        let output = decode_pcap(&evidence(&b), meta(), &mut state, &Limits::default())
            .unwrap()
            .encode();
        assert_eq!(state.asn_width(0), 4);
        assert_eq!(state.generation, 0);
        assert!(output.contains("\"four_octet_asn\":65636"));
    }

    #[test]
    fn notification_exposes_codes_and_starts_a_new_generation() {
        let mut b = vec![0xff; 16];
        b.extend_from_slice(&[0, 23, 3, 6, 2, 0xde, 0xad]);
        let mut state = SessionState::default();
        let output = decode_pcap(&evidence(&b), meta(), &mut state, &Limits::default())
            .unwrap()
            .encode();
        assert!(output.contains("\"code\":6"));
        assert!(output.contains("\"subcode\":2"));
        assert!(output.contains("\"data_sha256\""));
        assert!(output.contains(&format!(
            "\"data_sha256\":\"{}\"",
            payload_sha256(&[0xde, 0xad])
        )));
        assert_eq!(state.generation, 1);
    }

    #[test]
    fn missing_direction_never_mutates_open_state_or_invents_scope() {
        let mut b = vec![0xff; 16];
        b.extend_from_slice(&[0, 37, 1, 4, 0xfd, 0xe8, 0, 90]);
        b.extend_from_slice(&[192, 0, 2, 2, 8, 2, 6, 65, 4, 0, 1, 0, 100]);
        let mut metadata = meta();
        metadata.direction = None;
        let mut state = SessionState::default();
        let output = decode_pcap(&evidence(&b), metadata, &mut state, &Limits::default())
            .unwrap()
            .encode();
        assert_eq!(state.asn_width(0), 2);
        assert_eq!(state.generation, 0);
        assert!(output.contains("direction_missing_state_not_updated"));
    }

    #[test]
    fn path_attribute_ranges_expose_real_digests() {
        let mut state = SessionState::default();
        let output = decode_pcap(&evidence(&update()), meta(), &mut state, &Limits::default())
            .unwrap()
            .encode();
        assert!(output.contains(&format!("\"sha256\":\"{}\"", payload_sha256(&[0]))));
    }

    #[test]
    fn multiprotocol_attribute_cannot_read_past_its_declared_extent() {
        let mut b = vec![0xff; 16];
        b.extend_from_slice(&[
            0, 0, 2, 0, 7, 0x80, 14, 7, 0, 1, 1, 4, 192, 0, 2, 1, 0, 0, 0, 0,
        ]);
        let length = u16::try_from(b.len()).unwrap();
        b[16..18].copy_from_slice(&length.to_be_bytes());
        let mut state = SessionState::default();
        assert!(decode_pcap(&evidence(&b), meta(), &mut state, &Limits::default()).is_err());
    }

    #[test]
    fn route_refresh_exposes_address_family_metadata() {
        let mut b = vec![0xff; 16];
        b.extend_from_slice(&[0, 23, 5, 0, 1, 0, 1]);
        let mut state = SessionState::default();
        let output = decode_pcap(&evidence(&b), meta(), &mut state, &Limits::default())
            .unwrap()
            .encode();
        assert!(output.contains("\"afi\":1"));
        assert!(output.contains("\"safi\":1"));
        assert_eq!(state.generation, 0);
    }

    #[test]
    fn unsupported_open_version_is_rejected_before_state_mutation() {
        let mut b = vec![0xff; 16];
        b.extend_from_slice(&[0, 29, 1, 3, 0xfd, 0xe8, 0, 90]);
        b.extend_from_slice(&[192, 0, 2, 2, 0]);
        let mut state = SessionState::default();
        assert!(decode_pcap(&evidence(&b), meta(), &mut state, &Limits::default()).is_err());
        assert_eq!(state.asn_width(0), 2);
        assert_eq!(state.generation, 0);
    }

    #[test]
    fn imported_observation_has_the_same_normalized_schema_but_different_source() {
        let prefix = Prefix::ipv4([203, 0, 113, 99], 24).unwrap();
        let output = normalize_imported(
            ImportedRouteObservation {
                source_id: "collector-a".into(),
                record_id: "row-9".into(),
                observed_at_ns: Some(100),
                session: Some("peer-session".into()),
                peer: Some("198.51.100.2".into()),
                local: None,
                action: RouteAction::Announce,
                prefix,
                attributes: PathAttributes::default(),
            },
            &Limits::default(),
        )
        .unwrap()
        .encode();
        assert!(output.contains("pcap-evidence.bgp.route-evidence.v1"));
        assert!(output.contains("\"source_kind\":\"imported\""));
        assert!(output.contains("203.0.113.0"));
        assert!(output.contains("imported_observation_not_wire_verified"));
        assert!(!output.contains("\"semantic_identity\""));
    }

    #[test]
    fn malformed_attribute_does_not_create_a_route_record() {
        let mut b = vec![0xff; 16];
        b.extend_from_slice(&[0, 0, 2, 0, 0, 0, 6, 0x40, 1, 1, 0, 0]);
        let length = u16::try_from(b.len()).unwrap();
        b[16..18].copy_from_slice(&length.to_be_bytes());
        let mut state = SessionState::default();
        assert!(decode_pcap(&evidence(&b), meta(), &mut state, &Limits::default()).is_err());
    }
}
