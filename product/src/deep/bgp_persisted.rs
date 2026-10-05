//! Bounded offline consumers of sealed raw stores. Projections are never inputs.
//! Store seals establish integrity only; source authenticity and endpoint truth
//! remain unavailable. All original occurrences and alternatives are retained.
use super::{
    bgp, bgp_association as association, bgp_bmp, bgp_bmp_store,
    bgp_import::ObservationClock,
    bgp_mrt::MrtLimits,
    bgp_mrt_store,
    bgp_policy::{
        self, AgeEvidence, AgeRule, BestPathInputs, MedEvidence, MedRule, PolicyCandidate,
        PolicyConfig,
    },
    bgp_rib::{PathId, RouteKey, RouteStatus, VersionDisposition},
    bgp_session::{Family, PartitionKind},
    bgp_state::{Observation, PrefixIdentity},
    bgp_store,
    model::{bad, Limits},
};
use pcap_evidence::{json::Json, sha256, Error, ErrorCode, Result};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    io::Read,
    net::{IpAddr, Ipv4Addr},
    path::Path,
};

pub const PROFILE_SCHEMA: &str = "pcap-evidence.bgp.persisted-policy.v1";
pub const MAX_PROFILE_BYTES: usize = 65_536;

#[derive(Clone, Debug)]
pub struct RouterInput {
    pub source_id: String,
    pub session: String,
    pub peer: Option<String>,
    pub locally_originated: Option<bool>,
    pub igp_metric: Option<u32>,
    pub router_id: Option<Ipv4Addr>,
    pub ebgp: Option<bool>,
    pub neighbor_address: Option<IpAddr>,
}
#[derive(Clone, Debug)]
pub struct PolicyProfile {
    pub config: PolicyConfig,
    pub router_inputs: Vec<RouterInput>,
}
impl PolicyProfile {
    /// UTF-8 LF lines, `key=value`; exact header keys appear once. Router rows
    /// use 8 `|`-separated fields. `unknown` is typed absent evidence. No escapes,
    /// comments, blank lines, whitespace normalization, or implicit defaults.
    pub fn parse(bytes: &[u8], limits: &Limits) -> Result<Self> {
        limits.validate()?;
        if bytes.is_empty()
            || bytes.len()
                > MAX_PROFILE_BYTES
                    .min(limits.input_bytes)
                    .min(limits.retained_bytes)
        {
            return Err(Error::limit("bgp_policy_profile"));
        }
        let text = std::str::from_utf8(bytes)
            .map_err(|_| bad("bgp_policy_profile", 0, "profile must be UTF-8"))?;
        let mut headers = BTreeMap::new();
        let mut routers = Vec::new();
        let mut identities = BTreeSet::new();
        for line in text.strip_suffix('\n').unwrap_or(text).split('\n') {
            let (key, value) = line
                .split_once('=')
                .ok_or_else(|| bad("bgp_policy_profile", 0, "key=value line required"))?;
            if value.is_empty()
                || value.len() > 4096
                || value.chars().any(char::is_control)
                || value.trim() != value
            {
                return Err(bad(
                    "bgp_policy_profile",
                    0,
                    "bounded exact nonempty value required",
                ));
            }
            if key == "router_input" {
                if routers.len() >= limits.elements.min(256) {
                    return Err(Error::limit("bgp_policy_router_inputs"));
                }
                let fields: Vec<_> = value.split('|').collect();
                if fields.len() != 8 || fields.iter().any(|v| v.is_empty() || v.trim() != *v) {
                    return Err(bad(
                        "bgp_policy_router_input",
                        0,
                        "eight exact fields required",
                    ));
                }
                for field in &fields[..3] {
                    identity(field)?;
                }
                let peer = optional_text(fields[2]);
                let row = RouterInput {
                    source_id: fields[0].into(),
                    session: fields[1].into(),
                    peer: peer.clone(),
                    locally_originated: optional_bool(fields[3])?,
                    igp_metric: optional_u32(fields[4])?,
                    router_id: optional_ip(fields[5])?,
                    ebgp: optional_bool(fields[6])?,
                    neighbor_address: optional_ip(fields[7])?,
                };
                if !identities.insert((row.source_id.clone(), row.session.clone(), peer)) {
                    return Err(bad(
                        "bgp_policy_router_input",
                        0,
                        "duplicate scoped router input",
                    ));
                }
                routers.push(row);
            } else if matches!(
                key,
                "schema"
                    | "provenance"
                    | "comparison_context"
                    | "missing_local_preference"
                    | "med_rule"
                    | "age_rule"
            ) {
                if headers.insert(key, value).is_some() {
                    return Err(bad("bgp_policy_profile", 0, "duplicate header"));
                }
            } else {
                return Err(bad("bgp_policy_profile", 0, "unknown profile key"));
            }
        }
        let required = |key| {
            headers
                .get(key)
                .copied()
                .ok_or_else(|| bad("bgp_policy_profile", 0, "required header missing"))
        };
        if required("schema")? != PROFILE_SCHEMA {
            return Err(Error::new(
                ErrorCode::UnsupportedVersion,
                0,
                "bgp_policy_profile",
                "unsupported profile version",
            ));
        }
        let provenance = required("provenance")?;
        let context = required("comparison_context")?;
        identity(provenance)?;
        identity(context)?;
        let med_rule = match required("med_rule")? {
            "same_neighbor_as" => Some(MedRule::SameNeighborAs),
            "compare_all" => Some(MedRule::CompareAll),
            "skip" => Some(MedRule::Skip),
            "unknown" => None,
            _ => return Err(bad("bgp_policy_profile", 0, "invalid MED rule")),
        };
        let age_rule = match required("age_rule")? {
            "same_clock" => Some(AgeRule::SameClock),
            "skip" => Some(AgeRule::Skip),
            "unknown" => None,
            _ => return Err(bad("bgp_policy_profile", 0, "invalid age rule")),
        };
        Ok(Self {
            config: PolicyConfig {
                provenance: provenance.into(),
                comparison_context: context.into(),
                missing_local_preference: optional_u32(required("missing_local_preference")?)?,
                med_rule,
                age_rule,
            },
            router_inputs: routers,
        })
    }
    pub fn read(path: &Path, limits: &Limits) -> Result<Self> {
        let bytes = bounded_read(path, MAX_PROFILE_BYTES.min(limits.input_bytes) as u64)?;
        Self::parse(&bytes, limits)
    }
}
// Optional native labels preserve the imported owner's existing grammar. The
// profile's versioned text decoder owns its escaping; queries compare raw text.
fn native_optional_identity(value: &str) -> Result<()> {
    if value.len() > 1024 || value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(bad(
            "bgp_persisted_identity",
            0,
            "bounded control-free native identity required",
        ));
    }
    Ok(())
}
fn identity(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 1024
        || value.trim() != value
        || value.chars().any(char::is_control)
        || value.contains('|')
    {
        return Err(bad(
            "bgp_persisted_identity",
            0,
            "exact bounded identity required",
        ));
    }
    Ok(())
}
fn optional_text(value: &str) -> Option<String> {
    (value != "unknown").then(|| value.into())
}
fn optional_bool(value: &str) -> Result<Option<bool>> {
    match value {
        "true" => Ok(Some(true)),
        "false" => Ok(Some(false)),
        "unknown" => Ok(None),
        _ => Err(bad(
            "bgp_policy_profile",
            0,
            "true, false or unknown required",
        )),
    }
}
fn optional_u32(value: &str) -> Result<Option<u32>> {
    if value == "unknown" {
        return Ok(None);
    };
    if value.is_empty()
        || !value.bytes().all(|b| b.is_ascii_digit())
        || value.len() > 1 && value.starts_with('0')
    {
        return Err(bad(
            "bgp_policy_profile",
            0,
            "canonical u32 or unknown required",
        ));
    }
    value
        .parse()
        .map(Some)
        .map_err(|_| bad("bgp_policy_profile", 0, "u32 out of range"))
}
fn optional_ip<T: std::str::FromStr + ToString>(value: &str) -> Result<Option<T>> {
    if value == "unknown" {
        return Ok(None);
    }
    let address: T = value
        .parse()
        .map_err(|_| bad("bgp_policy_profile", 0, "invalid address"))?;
    if address.to_string() != value {
        return Err(bad("bgp_policy_profile", 0, "canonical address required"));
    }
    Ok(Some(address))
}
fn bounded_read(path: &Path, maximum: u64) -> Result<Vec<u8>> {
    let mut f = File::open(path)?;
    if !f.metadata()?.is_file() || f.metadata()?.len() > maximum {
        return Err(Error::limit("bgp_persisted_input"));
    }
    let mut bytes = Vec::new();
    f.by_ref()
        .take(maximum.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > maximum {
        return Err(Error::limit("bgp_persisted_input"));
    }
    Ok(bytes)
}

pub mod query;
pub use query::*;
pub mod analysis;
#[derive(Clone, Debug)]
pub struct SelectorOccurrence {
    pub native_event_index: Option<usize>,
    pub observation_index: usize,
    pub route_index: usize,
    pub occurrence_ref: Json,
    pub clock: ObservationClock,
    pub observed_at_ns: Option<i64>,
}
#[derive(Clone, Debug)]
pub struct SelectorVersion {
    pub native_version_index: Option<usize>,
    pub attribute_identity: String,
    pub disposition: VersionDisposition,
    pub occurrences: Vec<SelectorOccurrence>,
}
pub type RetainedRouteVersion = SelectorVersion;
pub type RouteOccurrence = SelectorOccurrence;
#[derive(Clone, Debug)]
struct SourceRouteOccurrence {
    key: RouteKey,
    lifecycle: Option<u64>,
    occurrence: SelectorOccurrence,
}

#[derive(Clone, Debug)]
struct RouteRow {
    id: String,
    key: RouteKey,
    status: RouteStatus,
    collector: bool,
    current: bool,
    lifecycle: Option<u64>,
    original_partition: Option<String>,
    alternatives: Json,
    version_occurrences: Json,
    selector_versions: Vec<SelectorVersion>,
    attributes: Option<Json>,
    witnesses: Vec<String>,
    checkpoint: Option<String>,
    clock: ObservationClock,
    observed_at_ns: Option<i64>,
    rejection: Option<Json>,
}
impl RouteRow {
    fn status_name(&self) -> &'static str {
        if self.collector {
            "collector_candidate"
        } else {
            status_name(self.status)
        }
    }
    fn json(&self) -> Json {
        self.json_projection(true)
    }
    fn evidence_json(&self) -> Json {
        let Json::Object(mut fields) = self.json() else {
            unreachable!()
        };
        fields.push(("version_occurrences", self.version_occurrences.clone()));
        Json::Object(fields)
    }
    fn inspect_evidence(&self, depth: usize, nodes: &mut usize, limits: &Limits) -> Result<()> {
        inspect_borrowed(&self.alternatives, depth + 1, nodes, limits)?;
        inspect_borrowed(&self.version_occurrences, depth + 1, nodes, limits)?;
        let Json::Object(mut fields) = self.json_projection(false) else {
            unreachable!()
        };
        fields.retain(|(key, _)| *key != "alternatives");
        inspect_borrowed(&Json::Object(fields), depth, nodes, limits)?;
        Ok(())
    }
    fn evidence_spans(&self) -> usize {
        reference_spans(&self.alternatives)
            .saturating_add(reference_spans(&self.version_occurrences))
    }
    fn evidence_encoded_len(&self, cap: usize) -> Result<usize> {
        let base = self.encoded_len(cap)?;
        let closure = self.version_occurrences.encoded_len_bounded(cap)?;
        let extra = Json::object([("version_occurrences", Json::Null)])
            .encoded_len_bounded(cap)?
            .saturating_sub(5);
        base.checked_add(closure)
            .and_then(|v| v.checked_add(extra))
            .filter(|v| *v <= cap)
            .ok_or_else(|| Error::limit("bgp_persisted_evidence_output"))
    }
    // Measure the borrowed alternatives first; no attribute subtree is cloned.
    fn encoded_len(&self, cap: usize) -> Result<usize> {
        let alternatives = self.alternatives.encoded_len_bounded(cap)?;
        let base = self.json_projection(false).encoded_len_bounded(cap)?;
        let size = base
            .checked_sub(4)
            .and_then(|n| n.checked_add(alternatives))
            .ok_or_else(|| Error::limit("bgp_persisted_output"))?;
        if size > cap {
            return Err(Error::limit("bgp_persisted_output"));
        }
        Ok(size)
    }
    fn json_projection(&self, include_alternatives: bool) -> Json {
        Json::object([
            ("id", self.id.clone().into()),
            ("source_id", self.key.scope.source.source_id.clone().into()),
            (
                "source_kind",
                if self.key.scope.source.kind == PartitionKind::Captured {
                    "captured"
                } else {
                    "imported"
                }
                .into(),
            ),
            (
                "partition_id",
                self.key.scope.source.partition_id.clone().into(),
            ),
            (
                "original_partition_id",
                self.original_partition
                    .clone()
                    .map_or(Json::Null, Json::from),
            ),
            (
                "checkpoint_id",
                self.checkpoint.clone().map_or(Json::Null, Json::from),
            ),
            ("session", self.key.scope.session.clone().into()),
            ("generation", self.key.scope.generation.into()),
            (
                "direction",
                self.key.scope.direction.map_or(Json::Null, Json::from),
            ),
            (
                "peer",
                self.key.scope.peer.clone().map_or(Json::Null, Json::from),
            ),
            ("afi", self.key.family.afi.into()),
            ("safi", self.key.family.safi.into()),
            (
                "prefix",
                format!("{}/{}", self.key.prefix.address, self.key.prefix.length).into(),
            ),
            (
                "path_id",
                match self.key.path_id {
                    PathId::Absent => Json::Null,
                    PathId::Present(v) => v.into(),
                    PathId::Unknown => "unknown".into(),
                },
            ),
            ("status", self.status_name().into()),
            (
                "alternatives",
                if include_alternatives {
                    self.alternatives.clone()
                } else {
                    Json::Null
                },
            ),
            ("native_current", self.current.into()),
            ("rejection", self.rejection.clone().unwrap_or(Json::Null)),
            (
                "captured_lifecycle",
                self.lifecycle.map_or(Json::Null, Json::from),
            ),
            ("clock", clock_json(&self.clock)),
            (
                "observed_at_ns",
                self.observed_at_ns
                    .map_or(Json::Null, |value| value.to_string().into()),
            ),
            ("source_authenticated", false.into()),
            ("endpoint_state_claimed", false.into()),
        ])
    }
}
/// Only a successful sealed raw-source replay can construct this value.
pub struct VerifiedStore {
    receipt: Json,
    digest: String,
    namespace: String,
    rows: Vec<RouteRow>,
    observations: Vec<Observation>,
    captured_observation_evidence: Vec<bgp_store::CapturedObservationEvidence>,
    peer_relationship: Option<bgp::PeerRelationship>,
    source_events: Vec<Json>,
    captured_source_events: Vec<bgp_store::CapturedSourceEvent>,
    imported_source_events: Vec<super::bgp_import::ImportedSourceEvent>,
    source_route_occurrences: Vec<SourceRouteOccurrence>,
}
type NativePolicyScope = (
    String,
    Option<u8>,
    Option<(String, u64, Option<String>)>,
    PrefixIdentity,
);
impl VerifiedStore {
    pub fn load(
        path: &Path,
        maximum: u64,
        mrt_limits: MrtLimits,
        limits: Limits,
        options: bgp_mrt_store::MrtReplayOptions,
    ) -> Result<Self> {
        limits.validate()?;
        let mut f = File::open(path)?;
        if !f.metadata()?.is_file() || f.metadata()?.len() > maximum {
            return Err(Error::limit("bgp_store_disk"));
        }
        let mut magic = [0u8; 8];
        f.read_exact(&mut magic)?;
        drop(f);
        let mut source_events = Vec::new();
        let mut captured_source_events = Vec::new();
        let mut imported_source_events = Vec::new();
        let mut captured_rejections = Vec::new();
        let mut captured_entry_evidence = Vec::new();
        let mut captured_observation_evidence = Vec::new();
        let (receipt, digest, namespace, entries, rejections, observations, collector) = if &magic
            == bgp_store::MAGIC
        {
            if options.peer_relationship.is_some() {
                return Err(bad(
                    "bgp_persisted_options",
                    0,
                    "capture replay does not accept imported relationship override",
                ));
            }
            let a = bgp_store::replay(path, maximum, limits.clone())?;
            let mut event_bytes = 0usize;
            let mut event_nodes = 0usize;
            for event in &a.source_events {
                if let Some(c) = &event.continuity {
                    let o = a.observations.get(c.observation_index).ok_or_else(|| {
                        bad("bgp_persisted_continuity", 0, "bound observation missing")
                    })?;
                    let evidence =
                        a.observation_evidence
                            .get(c.observation_index)
                            .ok_or_else(|| {
                                bad(
                                    "bgp_persisted_continuity",
                                    0,
                                    "bound journal evidence missing",
                                )
                            })?;
                    if o.sha256() != c.observation_sha256
                        || evidence.source_record_index != event.source_record_index
                        || evidence.journal_record_sha256 != event.journal_record_sha256
                        || evidence.source_start != event.source_start
                        || evidence.source_end != event.source_end
                        || event.scopes.len() != 1
                        || event.scopes[0].lifecycle != evidence.lifecycle
                        || o.source().session.as_deref() != Some(c.decision.scope.session.as_str())
                        || c.decision.scope.session != event.scopes[0].session.to_string()
                        || c.decision.scope.source.source_id != o.source().source_id
                        || c.decision.scope.source.partition_id
                            != format!(
                                "capture-namespace-sha256:{}",
                                sha256::hex(&a.receipt.capture_namespace)
                            )
                    {
                        return Err(bad(
                            "bgp_persisted_continuity",
                            0,
                            "decoded boundary occurrence binding mismatch",
                        ));
                    }
                }
                // Typed archive bounds its own shape; admit consumer copy before serialization.
                let size = event.retained_charge();
                event_bytes = event_bytes
                    .checked_add(size.saturating_mul(6))
                    .ok_or_else(|| Error::limit("bgp_persisted_source_events"))?;
                if event_bytes > limits.retained_bytes
                    || event_bytes > limits.work
                    || source_events.len() >= limits.elements
                {
                    return Err(Error::limit("bgp_persisted_source_events"));
                }
                event_nodes = event_nodes
                    .checked_add(event.projection_nodes())
                    .ok_or_else(|| Error::limit("bgp_persisted_source_events"))?;
                if event_nodes > limits.fields || event.projection_depth() > limits.depth {
                    return Err(Error::limit("bgp_persisted_source_events"));
                }
                source_events.push(event.json());
            }
            captured_source_events = a.source_events;
            captured_rejections = a.route_rejections;
            captured_entry_evidence = a.route_entry_evidence;
            captured_observation_evidence = a.observation_evidence;
            let digest = sha256::hex(&a.receipt.terminal_sha256);
            let namespace = format!(
                "capture-namespace-sha256:{}",
                sha256::hex(&a.receipt.capture_namespace)
            );
            (
                a.receipt.json(),
                digest,
                namespace,
                a.route_entries,
                Vec::new(),
                a.observations,
                Vec::new(),
            )
        } else if &magic == bgp_mrt_store::MAGIC {
            let a = bgp_mrt_store::replay_with_options(
                path,
                maximum,
                mrt_limits,
                limits.clone(),
                options,
            )?;
            preflight_native_clone(&a.bgp4mp_rib, a.state.observations(), &limits)?;
            let mut collector = Vec::new();
            let mut collector_bytes = 0usize;
            for c in &a.candidates {
                let o = a.candidate_observation(c)?;
                let r = &o.routes()[c.route_index];
                collector_bytes = collector_bytes
                    .checked_add(
                        r.attributes()
                            .encoded_len_bounded(limits.retained_bytes)?
                            .saturating_mul(3)
                            .saturating_add(4096),
                    )
                    .ok_or_else(|| Error::limit("bgp_persisted_collector"))?;
                if collector.len() >= limits.elements
                    || collector_bytes > limits.retained_bytes
                    || collector_bytes > limits.work
                {
                    return Err(Error::limit("bgp_persisted_collector"));
                }
                let p = super::bgp_session::SourcePartition::from_import_context(
                    o.import_context()
                        .ok_or_else(|| bad("bgp_persisted_import", 0, "context missing"))?,
                    &limits,
                )?;
                let key = RouteKey {
                    scope: super::bgp_rib::RibScope {
                        source: p,
                        session: c.session.clone(),
                        generation: o.source().generation.unwrap_or(0),
                        direction: None,
                        peer: c.peer.clone(),
                    },
                    family: Family {
                        afi: c.prefix.afi,
                        safi: c.prefix.safi,
                    },
                    path_id: match c.path_id {
                        super::bgp_state::RoutePathId::Absent => PathId::Absent,
                        super::bgp_state::RoutePathId::Present(v) => PathId::Present(v),
                    },
                    prefix: c.prefix.clone(),
                };
                let imported_namespace = format!(
                    "mrt-source-sha256:{}:checkpoint:{}",
                    sha256::hex(&a.receipt.source_sha256),
                    a.receipt.checkpoint_id
                );
                let occurrence_charge = o
                    .normalized()
                    .encoded_len_bounded(limits.retained_bytes)?
                    .saturating_add(4096)
                    .saturating_mul(8);
                collector_bytes = collector_bytes
                    .checked_add(occurrence_charge)
                    .ok_or_else(|| Error::limit("bgp_persisted_collector"))?;
                if collector_bytes > limits.retained_bytes || collector_bytes > limits.work {
                    return Err(Error::limit("bgp_persisted_collector"));
                }
                let clock = o.import_context().expect("checked context").clock.clone();
                let occurrence_ref =
                    occurrence_reference(o, c.route_index, &key, None, &imported_namespace, &clock);
                let encoded_identity = r.attribute_identity().encode_bounded(limits.input_bytes)?;
                let attribute_identity = format!(
                    "sha256:{}",
                    sha256::hex(&sha256::digest(encoded_identity.as_bytes()))
                );
                let version_occurrences = Json::array([Json::object([
                    ("attribute_identity", attribute_identity.clone().into()),
                    ("disposition", "collector_candidate".into()),
                    ("native_version_index", Json::Null),
                    ("origin_binding", "unavailable_collector_candidate".into()),
                    ("occurrences", Json::array([occurrence_ref.clone()])),
                ])]);
                let selector_versions = vec![SelectorVersion {
                    native_version_index: None,
                    attribute_identity,
                    disposition: VersionDisposition::Conflicting,
                    occurrences: vec![SelectorOccurrence {
                        native_event_index: None,
                        observation_index: c.observation_index,
                        route_index: c.route_index,
                        occurrence_ref,
                        clock,
                        observed_at_ns: c.observed_at_ns,
                    }],
                }];
                collector.push(RouteRow {
                    id: format!("collector:{}:{}", c.record_index, c.entry_index),
                    key,
                    status: RouteStatus::Unresolved,
                    collector: true,
                    current: false,
                    lifecycle: None,
                    original_partition: None,
                    alternatives: Json::array([Json::object([
                        ("attributes", r.attributes().clone()),
                        ("observation_sha256", sha256::hex(&o.sha256()).into()),
                        ("record_id", c.record_id.clone().into()),
                    ])]),
                    version_occurrences,
                    selector_versions,
                    attributes: None,
                    witnesses: vec![c.record_id.clone()],
                    checkpoint: Some(c.checkpoint_id.clone()),
                    clock: o.import_context().expect("checked context").clock.clone(),
                    observed_at_ns: c.observed_at_ns,
                    rejection: None,
                });
            }
            // Finish archive-owned candidate validation before moving its vectors.
            imported_source_events = a.source_events;
            source_events = a.bgp4mp_events;
            let digest = sha256::hex(&a.receipt.terminal_sha256);
            let namespace = format!(
                "mrt-source-sha256:{}:checkpoint:{}",
                sha256::hex(&a.receipt.source_sha256),
                a.receipt.checkpoint_id
            );
            (
                a.receipt.json(),
                digest,
                namespace,
                a.bgp4mp_rib.entries().values().cloned().collect(),
                a.bgp4mp_rib.rejections().to_vec(),
                a.state.observations().to_vec(),
                collector,
            )
        } else if &magic == bgp_bmp_store::MAGIC {
            let bmp_limits = bmp_profile(&mrt_limits);
            let a = bgp_bmp_store::replay_with_options(
                path,
                maximum,
                bmp_limits,
                limits.clone(),
                bgp_bmp_store::BmpReplayOptions {
                    peer_relationship: options.peer_relationship,
                },
            )?;
            preflight_native_clone(&a.bmp_rib, a.state.observations(), &limits)?;
            imported_source_events = a.source_events;
            source_events = a.bmp_events;
            let digest = sha256::hex(&a.receipt.terminal_sha256);
            let namespace = format!(
                "bmp-source-sha256:{}:checkpoint:{}",
                sha256::hex(&a.receipt.source_sha256),
                a.receipt.checkpoint_id
            );
            (
                a.receipt.json(),
                digest,
                namespace,
                a.bmp_rib.entries().values().cloned().collect(),
                a.bmp_rib.rejections().to_vec(),
                a.state.observations().to_vec(),
                Vec::new(),
            )
        } else {
            return Err(Error::new(
                ErrorCode::BadMagic,
                0,
                "bgp_store_magic",
                "sealed captured/MRT/BMP source store required",
            ));
        };
        let mut rows = collector;
        let mut occurrence_count = rows
            .iter()
            .map(|r| {
                r.selector_versions
                    .iter()
                    .map(|v| v.occurrences.len())
                    .sum::<usize>()
            })
            .sum::<usize>();
        let mut occurrence_spans = 0usize;
        let mut occurrence_nodes = 0usize;
        let mut materialized_bytes = observations.iter().try_fold(0usize, |sum, o| {
            sum.checked_add(
                o.normalized()
                    .encoded_len_bounded(limits.retained_bytes)?
                    .saturating_mul(3),
            )
            .ok_or_else(|| Error::limit("bgp_persisted_rows"))
        })?;
        for row in &rows {
            materialized_bytes = materialized_bytes
                .checked_add(row.encoded_len(limits.retained_bytes)?.saturating_mul(3))
                .ok_or_else(|| Error::limit("bgp_persisted_rows"))?;
        }
        for (index, entry) in entries.iter().enumerate() {
            if rows.len() >= limits.elements {
                return Err(Error::limit("bgp_persisted_routes"));
            }
            materialized_bytes = materialized_bytes
                .checked_add(entry_charge(entry, &limits)?.saturating_mul(4))
                .ok_or_else(|| Error::limit("bgp_persisted_rows"))?;
            if materialized_bytes > limits.retained_bytes || materialized_bytes > limits.work {
                return Err(Error::limit("bgp_persisted_rows"));
            }
            let capture_evidence = captured_entry_evidence.get(index);
            let mut observation = None;
            for (oi, o) in observations.iter().enumerate().rev() {
                if o.source().record_id == entry.last_witness
                    && occurrence_matches(
                        entry,
                        oi,
                        o,
                        capture_evidence,
                        &captured_observation_evidence,
                        &namespace,
                        &limits,
                    )?
                {
                    observation = Some(o);
                    break;
                }
            }
            let context = observation.and_then(Observation::import_context);
            let scan_charge = observations
                .iter()
                .try_fold(0usize, |sum, o| {
                    sum.checked_add(
                        o.normalized()
                            .encoded_len_bounded(limits.input_bytes)?
                            .saturating_add(1024),
                    )
                    .ok_or_else(|| Error::limit("bgp_persisted_occurrence_work"))
                })?
                .checked_mul(entry.versions.len().saturating_add(1))
                .ok_or_else(|| Error::limit("bgp_persisted_occurrence_work"))?;
            let origin_comparisons = observations
                .iter()
                .try_fold(0usize, |n, o| {
                    n.checked_add(o.routes().len())
                        .ok_or_else(|| Error::limit("bgp_persisted_occurrence_work"))
                })?
                .checked_mul(entry.versions.iter().try_fold(0usize, |n, version| {
                    n.checked_add(version.occurrences.len())
                        .ok_or_else(|| Error::limit("bgp_persisted_occurrence_work"))
                })?)
                .ok_or_else(|| Error::limit("bgp_persisted_occurrence_work"))?;
            materialized_bytes = materialized_bytes
                .checked_add(scan_charge)
                .and_then(|n| n.checked_add(origin_comparisons))
                .ok_or_else(|| Error::limit("bgp_persisted_occurrence_work"))?;
            if materialized_bytes > limits.retained_bytes || materialized_bytes > limits.work {
                return Err(Error::limit("bgp_persisted_occurrence_work"));
            }
            let mut selector_versions = Vec::new();
            let mut current_witnesses = Vec::new();
            for (version_index, version) in entry.versions.iter().enumerate() {
                let mut occurrences = Vec::new();
                for (oi, o) in observations.iter().enumerate() {
                    if !occurrence_matches(
                        entry,
                        oi,
                        o,
                        capture_evidence,
                        &captured_observation_evidence,
                        &namespace,
                        &limits,
                    )? || !version.witnesses.contains(&o.source().record_id)
                    {
                        continue;
                    }
                    for (ri, route) in o.routes().iter().enumerate() {
                        if !route_matches_key(route, &entry.key)
                            || route.action() != bgp::RouteAction::Announce
                            || route.ambiguous_attributes()
                            || route.attributes() != &version.attributes
                        {
                            continue;
                        }
                        let encoded = route
                            .attribute_identity()
                            .encode_bounded(limits.input_bytes)?;
                        let attribute_identity = format!(
                            "sha256:{}",
                            sha256::hex(&sha256::digest(encoded.as_bytes()))
                        );
                        if attribute_identity != version.attribute_identity {
                            continue;
                        }
                        // Native producer stamps bind the exact observation and action ordinal
                        // to the actual version merged/appended by the authoritative reducer.
                        // Labels and equal attributes alone cannot supply a version origin.
                        let mut bindings = version.occurrences.iter().filter(|proof| {
                            proof.observation_sha256 == o.sha256() && proof.route_index == ri
                        });
                        let Some(origin) = bindings.next() else {
                            continue;
                        };
                        if bindings.next().is_some() {
                            return Err(bad(
                                "bgp_persisted_native_origin",
                                0,
                                "multiple native events bind one source route in one version",
                            ));
                        }
                        // Admission precedes copying the complete evidence closure and typed route.
                        occurrence_count = occurrence_count
                            .checked_add(1)
                            .ok_or_else(|| Error::limit("bgp_persisted_occurrence_refs"))?;
                        occurrence_spans = occurrence_spans
                            .checked_add(reference_spans(o.normalized()).saturating_mul(2))
                            .ok_or_else(|| Error::limit("bgp_persisted_occurrence_refs"))?;
                        inspect_borrowed(o.normalized(), 4, &mut occurrence_nodes, &limits)?;
                        admit_note_nodes(5, 5, &mut occurrence_nodes, &limits)?;
                        if occurrence_count > limits.elements || occurrence_spans > limits.spans {
                            return Err(Error::limit("bgp_persisted_occurrence_refs"));
                        }
                        let size = o.normalized().encoded_len_bounded(limits.retained_bytes)?;
                        materialized_bytes = materialized_bytes
                            .checked_add(size.saturating_add(4096).saturating_mul(8))
                            .ok_or_else(|| Error::limit("bgp_persisted_occurrence_refs"))?;
                        if materialized_bytes > limits.retained_bytes
                            || materialized_bytes > limits.work
                            || occurrences.len() >= limits.elements
                        {
                            return Err(Error::limit("bgp_persisted_occurrence_refs"));
                        }
                        let capture = captured_observation_evidence.get(oi);
                        let clock = observation_clock(o, &namespace);
                        let mut occurrence_ref =
                            occurrence_reference(o, ri, &entry.key, capture, &namespace, &clock);
                        if let Json::Object(fields) = &mut occurrence_ref {
                            if let Some((_, schema)) =
                                fields.iter_mut().find(|(key, _)| *key == "schema")
                            {
                                *schema = "pcap-evidence.bgp.route-occurrence-reference.v2".into();
                            }
                            let mut native_origin = origin.json();
                            if let Json::Object(origin_fields) = &mut native_origin {
                                origin_fields.push(("version_index", version_index.into()));
                            }
                            fields.push(("native_origin", native_origin));
                        }
                        if version.disposition == VersionDisposition::Current {
                            current_witnesses.push(sha256::hex(&o.sha256()));
                        }
                        occurrences.push(SelectorOccurrence {
                            native_event_index: Some(origin.event_index),
                            observation_index: oi,
                            route_index: ri,
                            occurrence_ref,
                            clock,
                            observed_at_ns: o.source().observed_at_ns,
                        });
                    }
                }
                selector_versions.push(SelectorVersion {
                    native_version_index: Some(version_index),
                    attribute_identity: version.attribute_identity.clone(),
                    disposition: version.disposition,
                    occurrences,
                });
            }
            let version_occurrences = Json::array(selector_versions.iter().map(|v| {
                Json::object([
                    ("attribute_identity", v.attribute_identity.clone().into()),
                    (
                        "native_version_index",
                        v.native_version_index.map_or(Json::Null, Json::from),
                    ),
                    (
                        "origin_binding",
                        if v.occurrences.is_empty() {
                            "unavailable"
                        } else {
                            "verified_native_version_occurrences"
                        }
                        .into(),
                    ),
                    (
                        "disposition",
                        format!("{:?}", v.disposition).to_lowercase().into(),
                    ),
                    (
                        "occurrences",
                        Json::array(v.occurrences.iter().map(|o| o.occurrence_ref.clone())),
                    ),
                ])
            }));
            let alternatives = Json::array(entry.versions.iter().map(|v| {
                Json::object([
                    ("attribute_identity", v.attribute_identity.clone().into()),
                    ("attributes", v.attributes.clone()),
                    (
                        "witnesses",
                        Json::array(v.witnesses.iter().cloned().map(Json::from)),
                    ),
                    (
                        "disposition",
                        format!("{:?}", v.disposition).to_lowercase().into(),
                    ),
                ])
            }));
            let versions: Vec<_> = entry
                .versions
                .iter()
                .filter(|v| v.disposition == VersionDisposition::Current)
                .collect();
            let mut key = entry.key.clone();
            if let Some(e) = capture_evidence {
                key.scope.source.partition_id = format!(
                    "{}:captured-lifecycle:{}",
                    key.scope.source.partition_id, e.lifecycle
                );
            }
            let witnesses = current_witnesses;
            rows.push(RouteRow {
                id: format!("rib:{index}"),
                key,
                status: entry.status,
                collector: false,
                current: capture_evidence.is_none_or(|e| e.current)
                    && entry.status == RouteStatus::Active,
                lifecycle: capture_evidence.map(|e| e.lifecycle),
                original_partition: capture_evidence
                    .map(|_| entry.key.scope.source.partition_id.clone()),
                alternatives,
                version_occurrences,
                selector_versions,
                attributes: if versions.len() == 1 {
                    Some(versions[0].attributes.clone())
                } else {
                    None
                },
                witnesses,
                checkpoint: context.map(|c| c.checkpoint_id.clone()),
                clock: observation
                    .map(|o| observation_clock(o, &namespace))
                    .unwrap_or_default(),
                observed_at_ns: observation.and_then(|o| o.source().observed_at_ns),
                rejection: None,
            });
        }
        // A rejection is an occurrence, separate from accepted route versions.
        // It cannot replace or become a current native route with the same key.
        for (index, (rejection, captured)) in rejections
            .iter()
            .map(|rejection| (rejection, None))
            .chain(captured_rejections.iter().map(|r| (&r.rejection, Some(r))))
            .enumerate()
        {
            if rows.len() >= limits.elements {
                return Err(Error::limit("bgp_persisted_routes"));
            }
            materialized_bytes = materialized_bytes
                .checked_add(rejection_charge(rejection).saturating_mul(6))
                .ok_or_else(|| Error::limit("bgp_persisted_rows"))?;
            if materialized_bytes > limits.retained_bytes || materialized_bytes > limits.work {
                return Err(Error::limit("bgp_persisted_rows"));
            }
            let (observation, capture_evidence) = if let Some(captured) = captured {
                let observation =
                    observations
                        .get(captured.observation_index)
                        .ok_or_else(|| {
                            bad("bgp_persisted_rejection", 0, "source observation missing")
                        })?;
                let evidence = captured_observation_evidence
                    .get(captured.observation_index)
                    .ok_or_else(|| {
                        bad("bgp_persisted_rejection", 0, "captured occurrence missing")
                    })?;
                if rejection.key.scope.source.kind != PartitionKind::Captured
                    || rejection.key.scope.source.partition_id != namespace
                    || observation.source().source_id != rejection.key.scope.source.source_id
                    || observation.source().session.as_deref() != Some(&rejection.key.scope.session)
                    || observation.source().generation != Some(rejection.key.scope.generation)
                    || observation.source().direction != rejection.key.scope.direction
                    || observation.source().peer != rejection.key.scope.peer
                    || observation.source().record_id != rejection.record_id
                    || !observation.routes().iter().any(|route| {
                        route.ambiguous_attributes()
                            && route.prefix() == &rejection.key.prefix
                            && route.prefix().afi == rejection.key.family.afi
                            && route.prefix().safi == rejection.key.family.safi
                            && match (route.path_id(), rejection.key.path_id) {
                                (super::bgp_state::RoutePathId::Absent, PathId::Absent) => true,
                                (super::bgp_state::RoutePathId::Present(a), PathId::Present(b)) => {
                                    a == b
                                }
                                _ => false,
                            }
                    })
                {
                    return Err(bad(
                        "bgp_persisted_rejection",
                        0,
                        "captured source scope mismatch",
                    ));
                }
                (observation, Some(evidence))
            } else {
                let observation = observations
                    .iter()
                    .find(|o| {
                        o.source().source_id == rejection.key.scope.source.source_id
                            && o.source().session.as_deref() == Some(&rejection.key.scope.session)
                            && o.source().generation == Some(rejection.key.scope.generation)
                            && o.source().direction == rejection.key.scope.direction
                            && o.source().peer == rejection.key.scope.peer
                            && o.source().record_id == rejection.record_id
                    })
                    .ok_or_else(|| {
                        bad("bgp_persisted_rejection", 0, "source observation missing")
                    })?;
                let context = observation
                    .import_context()
                    .ok_or_else(|| bad("bgp_persisted_rejection", 0, "import context missing"))?;
                if super::bgp_session::SourcePartition::from_import_context(context, &limits)?
                    != rejection.key.scope.source
                {
                    return Err(bad(
                        "bgp_persisted_rejection",
                        0,
                        "source partition mismatch",
                    ));
                }
                (observation, None)
            };
            let context = observation.import_context();
            let mut key = rejection.key.clone();
            if let Some(evidence) = capture_evidence {
                key.scope.source.partition_id = format!(
                    "{}:captured-lifecycle:{}",
                    key.scope.source.partition_id, evidence.lifecycle
                );
            }
            let digest = sha256::hex(&observation.sha256());
            rows.push(RouteRow {
                id: format!("rejected:{index}"),
                key,
                status: RouteStatus::Rejected,
                collector: false,
                current: false,
                lifecycle: capture_evidence.map(|e| e.lifecycle),
                original_partition: capture_evidence
                    .map(|_| rejection.key.scope.source.partition_id.clone()),
                alternatives: Json::array([]),
                version_occurrences: Json::array([]),
                selector_versions: Vec::new(),
                attributes: None,
                witnesses: vec![digest.clone()],
                checkpoint: context.map(|c| c.checkpoint_id.clone()),
                clock: context.map(|c| c.clock.clone()).unwrap_or_default(),
                observed_at_ns: observation.source().observed_at_ns,
                rejection: Some(Json::object([
                    ("reason", rejection.reason.clone().into()),
                    ("record_id", rejection.record_id.clone().into()),
                    ("observation_sha256", digest.clone().into()),
                    (
                        "occurrence_id",
                        observation_occurrence_id(observation, capture_evidence).into(),
                    ),
                ])),
            });
        }
        let mut source_route_occurrences = Vec::new();
        let mut source_occurrence_spans = occurrence_spans;
        for (oi, o) in observations.iter().enumerate() {
            for ri in 0..o.routes().len() {
                let charge = o
                    .normalized()
                    .encoded_len_bounded(limits.retained_bytes)?
                    .saturating_add(4096)
                    .saturating_mul(8);
                materialized_bytes = materialized_bytes
                    .checked_add(charge)
                    .ok_or_else(|| Error::limit("bgp_persisted_source_occurrences"))?;
                source_occurrence_spans = source_occurrence_spans
                    .checked_add(reference_spans(o.normalized()).saturating_mul(2))
                    .ok_or_else(|| Error::limit("bgp_persisted_source_occurrences"))?;
                if source_route_occurrences.len() >= limits.elements
                    || source_occurrence_spans > limits.spans
                    || materialized_bytes > limits.retained_bytes
                    || materialized_bytes > limits.work
                {
                    return Err(Error::limit("bgp_persisted_source_occurrences"));
                }
                let capture = captured_observation_evidence.get(oi);
                let mut key = observation_route_key(o, ri, &namespace, &limits)?;
                let clock = observation_clock(o, &namespace);
                let occurrence_ref = occurrence_reference(o, ri, &key, capture, &namespace, &clock);
                if let Some(e) = capture {
                    key.scope.source.partition_id = format!(
                        "{}:captured-lifecycle:{}",
                        key.scope.source.partition_id, e.lifecycle
                    );
                }
                source_route_occurrences.push(SourceRouteOccurrence {
                    key,
                    lifecycle: capture.map(|e| e.lifecycle),
                    occurrence: SelectorOccurrence {
                        native_event_index: None,
                        observation_index: oi,
                        route_index: ri,
                        occurrence_ref,
                        clock,
                        observed_at_ns: o.source().observed_at_ns,
                    },
                });
            }
        }
        let result = Self {
            receipt,
            digest,
            namespace,
            rows,
            observations,
            captured_observation_evidence,
            peer_relationship: options.peer_relationship,
            source_events,
            captured_source_events,
            imported_source_events,
            source_route_occurrences,
        };
        preflight_store(&result, &limits)?;
        Ok(result)
    }
    fn is_current(&self, o: &Observation, index: usize) -> bool {
        let Some(route) = o.routes().get(index) else {
            return false;
        };
        self.rows.iter().any(|r| {
            !r.collector
                && r.current
                && r.status == RouteStatus::Active
                && r.key.scope.source.source_id == o.source().source_id
                && r.key.scope.session == o.source().session.as_deref().unwrap_or("")
                && Some(r.key.scope.generation) == o.source().generation
                && r.key.scope.direction == o.source().direction
                && r.key.scope.peer == o.source().peer
                && &r.key.prefix == route.prefix()
                && match (r.key.path_id, route.path_id()) {
                    (PathId::Absent, super::bgp_state::RoutePathId::Absent) => true,
                    (PathId::Present(a), super::bgp_state::RoutePathId::Present(b)) => a == b,
                    _ => false,
                }
                && r.witnesses.contains(&sha256::hex(&o.sha256()))
                && r.lifecycle.is_none_or(|life| {
                    self.observations
                        .iter()
                        .position(|candidate| std::ptr::eq(candidate, o))
                        .and_then(|oi| self.captured_observation_evidence.get(oi))
                        .is_some_and(|e| e.lifecycle == life)
                })
        })
    }
    fn occurrence_id(&self, o: &Observation) -> String {
        let life = self
            .observations
            .iter()
            .position(|candidate| std::ptr::eq(candidate, o))
            .and_then(|i| self.captured_observation_evidence.get(i));
        observation_occurrence_id(o, life)
    }

    pub fn reference(&self) -> Json {
        Json::object([
            ("sealed_store", self.receipt.clone()),
            ("terminal_sha256", self.digest.clone().into()),
            ("original_namespace", self.namespace.clone().into()),
            (
                "peer_relationship",
                self.peer_relationship
                    .map_or("unknown", bgp::PeerRelationship::as_str)
                    .into(),
            ),
            (
                "peer_relationship_basis",
                if self.peer_relationship.is_some() {
                    "explicit_configuration"
                } else {
                    "default_unknown"
                }
                .into(),
            ),
            ("source_authenticated", false.into()),
        ])
    }
    pub fn query(&self, query: &Query, limits: &Limits) -> Result<String> {
        query.validate()?;
        if query.is_v2() {
            return self.query_evidence(query, limits);
        }
        limits.validate()?;
        preflight_envelope(self, limits)?;
        let empty = Json::object([
            ("schema", "pcap-evidence.bgp.persisted-query.v1".into()),
            ("store", self.reference()),
            ("routes", Json::array([])),
            ("endpoint_state_claimed", false.into()),
        ]);
        let (row_bytes, _) = preflight_output_rows(
            self.rows
                .iter()
                .filter(|r| query.matches(r, &self.observations)),
            limits,
            &empty,
        )?;
        let empty = empty.encoded_len_bounded(limits.output_bytes)?;
        let count = self
            .rows
            .iter()
            .filter(|r| query.matches(r, &self.observations))
            .count();
        guard_projection(
            empty
                .saturating_add(row_bytes)
                .saturating_add(count.saturating_sub(1)),
            limits,
        )?;
        let rows = Json::array(
            self.rows
                .iter()
                .filter(|r| query.matches(r, &self.observations))
                .map(RouteRow::json),
        );
        bounded_output(
            Json::object([
                ("schema", "pcap-evidence.bgp.persisted-query.v1".into()),
                ("store", self.reference()),
                ("routes", rows),
                ("endpoint_state_claimed", false.into()),
            ]),
            limits,
        )
    }
    /// Named evidence-closure projection; legacy query output remains v1.
    pub fn query_evidence(&self, query: &Query, limits: &Limits) -> Result<String> {
        self.query_v2(query, limits)
    }
    pub fn state_evidence(&self, limits: &Limits) -> Result<String> {
        self.query_evidence(&Query::default(), limits)
    }
    /// Immutable accepted-version carriers; observation indices refer only to this verified store.
    pub fn retained_route_versions(
        &self,
    ) -> impl Iterator<Item = (&RouteKey, Option<u64>, &RetainedRouteVersion)> {
        self.rows.iter().flat_map(|row| {
            row.selector_versions
                .iter()
                .map(move |version| (&row.key, row.lifecycle, version))
        })
    }
    pub fn source_route_occurrences(
        &self,
    ) -> impl Iterator<Item = (&RouteKey, Option<u64>, &SelectorOccurrence)> {
        self.source_route_occurrences
            .iter()
            .map(|v| (&v.key, v.lifecycle, &v.occurrence))
    }
    /// Canonical native source partition for every observation, including route-free evidence.
    /// Captured lifecycles remain separate native partitions. Original occurrence JSON
    /// retains its immutable namespace and explicit lifecycle separately.
    pub(super) fn observation_partition(
        &self,
        index: usize,
        limits: &Limits,
    ) -> Result<super::bgp_session::SourcePartition> {
        let o = self
            .observations
            .get(index)
            .ok_or_else(|| bad("bgp_persisted_observation", 0, "observation index missing"))?;
        if let Some(c) = o.import_context() {
            return super::bgp_session::SourcePartition::from_import_context(c, limits);
        }
        let lifecycle = self
            .captured_observation_evidence
            .get(index)
            .ok_or_else(|| {
                bad(
                    "bgp_persisted_observation",
                    0,
                    "captured lifecycle evidence missing",
                )
            })?
            .lifecycle;
        Ok(super::bgp_session::SourcePartition {
            kind: PartitionKind::Captured,
            source_id: o.source().source_id.clone(),
            partition_id: format!("{}:captured-lifecycle:{}", self.namespace, lifecycle),
        })
    }
    /// Match a newly applied decoded boundary against a verified captured
    /// occurrence. Lifecycle ownership is checked here; native scope effects
    /// are delegated to the reducer owner rather than inferred from JSON.
    pub(super) fn captured_continuity_match_charge(
        &self,
        observation_index: usize,
    ) -> Result<usize> {
        let observation = self
            .observations
            .get(observation_index)
            .ok_or_else(|| bad("bgp_persisted_continuity", 0, "observation index missing"))?;
        let source = observation.source();
        Ok(512usize
            .saturating_add(source.source_id.len())
            .saturating_add(source.session.as_ref().map_or(0, String::len))
            .saturating_add(source.peer.as_ref().map_or(0, String::len))
            .saturating_add(self.namespace.len()))
    }
    pub(super) fn captured_continuity_matches(
        &self,
        event_index: usize,
        observation_index: usize,
        limits: &Limits,
    ) -> Result<bool> {
        limits.validate()?;
        let event = self
            .captured_source_events
            .get(event_index)
            .ok_or_else(|| bad("bgp_persisted_continuity", 0, "source event index missing"))?;
        let Some(bound) = &event.continuity else {
            return Ok(false);
        };
        if !bound.decision.newly_applied {
            return Ok(false);
        }
        let observation = self
            .observations
            .get(observation_index)
            .ok_or_else(|| bad("bgp_persisted_continuity", 0, "observation index missing"))?;
        if observation.import_context().is_some() {
            return Ok(false);
        }
        let evidence = self
            .captured_observation_evidence
            .get(observation_index)
            .ok_or_else(|| bad("bgp_persisted_continuity", 0, "captured lifecycle missing"))?;
        if event.scopes.len() != 1 || event.scopes[0].lifecycle != evidence.lifecycle {
            return Ok(false);
        }
        let source = observation.source();
        let (Some(session), Some(generation)) = (&source.session, source.generation) else {
            return Ok(false);
        };
        let copy_charge = self.captured_continuity_match_charge(observation_index)?;
        if copy_charge > limits.retained_bytes || copy_charge > limits.work {
            return Err(Error::limit("bgp_persisted_continuity"));
        }
        let scope = super::bgp_rib::RibScope {
            source: super::bgp_session::SourcePartition {
                kind: PartitionKind::Captured,
                source_id: source.source_id.clone(),
                partition_id: self.namespace.clone(),
            },
            session: session.clone(),
            generation,
            direction: source.direction,
            peer: source.peer.clone(),
        };
        Ok(bound.decision.affects_scope(&scope))
    }
    pub fn observations(&self) -> &[Observation] {
        &self.observations
    }
    pub fn captured_source_events(&self) -> &[bgp_store::CapturedSourceEvent] {
        &self.captured_source_events
    }
    pub fn imported_source_events(&self) -> &[super::bgp_import::ImportedSourceEvent] {
        &self.imported_source_events
    }
    pub fn captured_observation_evidence(&self) -> &[bgp_store::CapturedObservationEvidence] {
        &self.captured_observation_evidence
    }
    pub fn policy(
        &self,
        query: &Query,
        profile: &PolicyProfile,
        limits: &Limits,
    ) -> Result<String> {
        self.policy_impl(query, profile, limits, query.is_v2())
    }
    pub fn policy_evidence(
        &self,
        query: &Query,
        profile: &PolicyProfile,
        limits: &Limits,
    ) -> Result<String> {
        self.policy_impl(query, profile, limits, true)
    }
    fn policy_impl(
        &self,
        query: &Query,
        profile: &PolicyProfile,
        limits: &Limits,
        evidence_profile: bool,
    ) -> Result<String> {
        query.validate()?;
        if query.is_observation_event() {
            return Err(bad(
                "bgp_persisted_policy_observation_event",
                0,
                "policy requires native candidate versions",
            ));
        }
        limits.validate()?;
        preflight_envelope(self, limits)?;
        let coverage = if evidence_profile {
            self.selector_coverage(query, limits)?
        } else {
            Json::Null
        };
        let selectors = if evidence_profile {
            query.specification()
        } else {
            Json::Null
        };
        if evidence_profile {
            let mut nodes = 0;
            inspect_borrowed(&coverage, 1, &mut nodes, limits)?;
            inspect_borrowed(&selectors, 1, &mut nodes, limits)?;
            guard_projection(
                coverage
                    .encoded_len_bounded(limits.output_bytes)?
                    .saturating_add(selectors.encoded_len_bounded(limits.output_bytes)?),
                limits,
            )?;
        }
        let mut envelope_fields = vec![
            (
                "schema",
                if evidence_profile {
                    "pcap-evidence.bgp.persisted-policy-result.v2"
                } else {
                    "pcap-evidence.bgp.persisted-policy-result.v1"
                }
                .into(),
            ),
            ("store", self.reference()),
            ("policy_results", Json::array([])),
            ("alternatives", Json::array([])),
            ("endpoint_state_claimed", false.into()),
        ];
        if evidence_profile {
            envelope_fields.push(("selector_coverage", coverage.clone()));
            envelope_fields.push(("selectors", selectors.clone()));
        }
        let envelope = Json::Object(envelope_fields);
        let (row_bytes, mut output_nodes) = preflight_output_rows(
            self.rows
                .iter()
                .filter(|r| query.matches(r, &self.observations)),
            limits,
            &envelope,
        )?;
        let mut closure_bytes = 0usize;
        let mut closure_spans = 0usize;
        if evidence_profile {
            for row in self
                .rows
                .iter()
                .filter(|r| query.matches(r, &self.observations))
            {
                inspect_borrowed(&row.version_occurrences, 3, &mut output_nodes, limits)?;
                closure_spans = closure_spans
                    .checked_add(row.evidence_spans())
                    .ok_or_else(|| Error::limit("bgp_persisted_policy_spans"))?;
                if closure_spans > limits.spans {
                    return Err(Error::limit("bgp_persisted_policy_spans"));
                }
                closure_bytes = closure_bytes
                    .checked_add(
                        row.evidence_encoded_len(limits.output_bytes)?
                            .saturating_sub(row.encoded_len(limits.output_bytes)?),
                    )
                    .ok_or_else(|| Error::limit("bgp_persisted_policy_evidence"))?;
            }
            guard_projection(row_bytes.saturating_add(closure_bytes), limits)?;
        }
        let row_bytes = row_bytes.saturating_add(closure_bytes);
        let envelope_bytes = envelope.encoded_len_bounded(limits.output_bytes)?;
        let row_count = self
            .rows
            .iter()
            .filter(|r| query.matches(r, &self.observations))
            .count();
        guard_projection(
            envelope_bytes
                .saturating_add(row_bytes)
                .saturating_add(row_count.saturating_sub(1)),
            limits,
        )?;
        let mut groups: BTreeMap<NativePolicyScope, Vec<PolicyCandidate>> = BTreeMap::new();
        for row in self
            .rows
            .iter()
            .filter(|r| query.matches(r, &self.observations))
        {
            let mut inputs = BestPathInputs::default();
            if let Some(attributes) = &row.attributes {
                inputs.local_preference =
                    number(attributes, "local_preference").and_then(|v| u32::try_from(v).ok());
                inputs.origin = number(attributes, "origin").and_then(|v| u8::try_from(v).ok());
                inputs.med = match member(attributes, "med") {
                    Some(Json::Number(v)) => u32::try_from(*v).ok().map(MedEvidence::Present),
                    Some(Json::Null) => Some(MedEvidence::Absent),
                    _ => None,
                };
                let (length, neighbor) = path_inputs(attributes);
                inputs.as_path_length = length;
                inputs.neighboring_as = neighbor;
            }
            if let Some(router) = profile.router_inputs.iter().find(|v| {
                v.source_id == row.key.scope.source.source_id
                    && v.session == row.key.scope.session
                    && v.peer == row.key.scope.peer
            }) {
                inputs.locally_originated = router.locally_originated;
                inputs.igp_metric = router.igp_metric;
                inputs.router_id = router.router_id;
                inputs.ebgp = router.ebgp;
                inputs.neighbor_address = router.neighbor_address;
            }
            inputs.age = row
                .clock
                .clock_id
                .as_ref()
                .zip(row.observed_at_ns)
                .and_then(|(clock, time)| {
                    u64::try_from(time).ok().map(|observed_order| AgeEvidence {
                        clock_id: format!("{:?}:{clock}", row.clock.policy),
                        observed_order,
                    })
                });
            groups
                .entry((
                    row.key.scope.source.partition_id.clone(),
                    row.key.scope.direction,
                    if row.key.scope.source.kind == PartitionKind::Captured {
                        None
                    } else {
                        Some((
                            row.key.scope.session.clone(),
                            row.key.scope.generation,
                            row.key.scope.peer.clone(),
                        ))
                    },
                    row.key.prefix.clone(),
                ))
                .or_default()
                .push(PolicyCandidate {
                    id: row.id.clone(),
                    key: row.key.clone(),
                    comparison_context: profile.config.comparison_context.clone(),
                    status: policy_native_status(row.status, row.current),
                    inputs,
                });
        }
        let mut encoded = Vec::new();
        let mut trace_bytes = 0usize;
        for candidates in groups.values() {
            let result = bgp_policy::evaluate(&profile.config, candidates, limits)?;
            trace_bytes = trace_bytes
                .checked_add(result.encoded_len(limits.output_bytes)?)
                .ok_or_else(|| Error::limit("bgp_persisted_policy_trace"))?;
            if trace_bytes
                > limits
                    .output_bytes
                    .min(limits.retained_bytes)
                    .min(limits.work)
            {
                return Err(Error::limit("bgp_persisted_policy_trace"));
            }
            guard_projection(
                trace_bytes
                    .saturating_add(row_bytes)
                    .saturating_add(envelope_bytes)
                    .saturating_add(row_count.saturating_sub(1))
                    .saturating_add(groups.len().saturating_sub(1)),
                limits,
            )?;
            // Exact nodes of the typed policy result: twelve members plus root,
            // five nodes per comparison, six per step, three per excluded row.
            let trace_nodes = result
                .comparisons
                .iter()
                .try_fold(13usize, |n, c| {
                    n.checked_add(5)
                        .and_then(|v| v.checked_add(c.steps.len().checked_mul(6)?))
                        .ok_or_else(|| Error::limit("bgp_persisted_fields"))
                })?
                .checked_add(result.excluded.len().saturating_mul(3))
                .and_then(|n| n.checked_add(result.unresolved.len()))
                .ok_or_else(|| Error::limit("bgp_persisted_fields"))?;
            output_nodes = output_nodes
                .checked_add(trace_nodes)
                .ok_or_else(|| Error::limit("bgp_persisted_fields"))?;
            if output_nodes > limits.fields {
                return Err(Error::limit("bgp_persisted_fields"));
            }
            encoded.push(result.to_json());
        }
        // The typed library results preserve their schema inside the sealed wrapper.
        let mut fields = vec![
            (
                "schema",
                if evidence_profile {
                    "pcap-evidence.bgp.persisted-policy-result.v2"
                } else {
                    "pcap-evidence.bgp.persisted-policy-result.v1"
                }
                .into(),
            ),
            ("store", self.reference()),
            ("policy_results", Json::array(encoded)),
            (
                "alternatives",
                Json::array(
                    self.rows
                        .iter()
                        .filter(|r| query.matches(r, &self.observations))
                        .map(|r| {
                            if evidence_profile {
                                r.evidence_json()
                            } else {
                                r.json()
                            }
                        }),
                ),
            ),
            ("endpoint_state_claimed", false.into()),
        ];
        if evidence_profile {
            fields.push(("selector_coverage", coverage));
            fields.push(("selectors", selectors));
        }
        bounded_output(Json::Object(fields), limits)
    }
    fn source_notes(&self, side: &str, limits: &Limits) -> Result<Vec<association::SelectionNote>> {
        let mut notes = Vec::new();
        let mut size = 0usize;
        let mut nodes = 0usize;
        let mut spans = 0usize;
        for (index, o) in self
            .observations
            .iter()
            .enumerate()
            .filter(|(_, o)| o.routes().is_empty())
        {
            let borrowed = o.normalized();
            inspect_borrowed(borrowed, 3, &mut nodes, limits)?;
            spans = spans
                .checked_add(reference_spans(borrowed))
                .ok_or_else(|| Error::limit("bgp_persisted_note_spans"))?;
            size = size
                .checked_add(
                    borrowed
                        .encoded_len_bounded(limits.input_bytes)?
                        .saturating_add(4096)
                        .saturating_mul(8),
                )
                .ok_or_else(|| Error::limit("bgp_persisted_source_notes"))?;
            if notes.len() >= limits.elements
                || spans > limits.spans
                || size > limits.retained_bytes
                || size > limits.work
            {
                return Err(Error::limit("bgp_persisted_source_notes"));
            }
            let kind = match o.kind() {
                super::bgp_state::ObservationKind::Open => association::SourceEventKind::Open,
                super::bgp_state::ObservationKind::Notification => {
                    association::SourceEventKind::Notification
                }
                super::bgp_state::ObservationKind::Keepalive => {
                    association::SourceEventKind::Keepalive
                }
                super::bgp_state::ObservationKind::RouteRefresh => {
                    association::SourceEventKind::RouteRefresh
                }
                super::bgp_state::ObservationKind::Reset => association::SourceEventKind::Reset,
                super::bgp_state::ObservationKind::Routes => {
                    if super::bgp_mrt_store::rib_support::end_of_rib_family(o)?.is_some() {
                        association::SourceEventKind::EndOfRib
                    } else if super::bgp_mrt_store::rib_support::route_projection_incomplete(o) {
                        association::SourceEventKind::Gap
                    } else {
                        association::SourceEventKind::SourceEvent
                    }
                }
            };
            let witness = Json::object([
                ("side", side.into()),
                ("source_store", self.reference()),
                ("note_plane", "normalized_observation".into()),
                ("observation_index", index.into()),
                ("source_occurrence_id", self.occurrence_id(o).into()),
                (
                    "normalized_observation_sha256",
                    sha256::hex(&o.sha256()).into(),
                ),
                ("normalized_observation", borrowed.clone()),
            ]);
            notes.push(association::SelectionNote::from_source_event(
                kind, &witness, limits,
            )?);
        }
        for (index, event) in self.captured_source_events.iter().enumerate() {
            let kind = match event.kind {
                bgp_store::CapturedSourceEventKind::Gap
                | bgp_store::CapturedSourceEventKind::DecodedGap => {
                    association::SourceEventKind::Gap
                }
                bgp_store::CapturedSourceEventKind::Reset
                | bgp_store::CapturedSourceEventKind::DecodedReset => {
                    association::SourceEventKind::Reset
                }
                bgp_store::CapturedSourceEventKind::EndSession => {
                    association::SourceEventKind::EndSession
                }
                bgp_store::CapturedSourceEventKind::Clear => association::SourceEventKind::Clear,
                bgp_store::CapturedSourceEventKind::RejectedContainer => {
                    association::SourceEventKind::RejectedContainer
                }
            };
            let borrowed = self.source_events.get(index).ok_or_else(|| {
                bad(
                    "bgp_persisted_source_event",
                    0,
                    "capture event reference missing",
                )
            })?;
            inspect_borrowed(borrowed, 3, &mut nodes, limits)?;
            spans = spans
                .checked_add(reference_spans(borrowed))
                .ok_or_else(|| Error::limit("bgp_persisted_note_spans"))?;
            size = size
                .checked_add(
                    borrowed
                        .encoded_len_bounded(limits.input_bytes)?
                        .saturating_add(4096)
                        .saturating_mul(8),
                )
                .ok_or_else(|| Error::limit("bgp_persisted_source_notes"))?;
            if notes.len() >= limits.elements
                || spans > limits.spans
                || size > limits.retained_bytes
                || size > limits.work
            {
                return Err(Error::limit("bgp_persisted_source_notes"));
            }
            let witness = Json::object([
                ("side", side.into()),
                ("source_store", self.reference()),
                ("note_plane", "source_container_event".into()),
                ("source_event_index", index.into()),
                ("source_event", borrowed.clone()),
            ]);
            notes.push(association::SelectionNote::from_source_event(
                kind, &witness, limits,
            )?);
        }
        for (index, event) in self.imported_source_events.iter().enumerate() {
            use super::bgp_import::ImportedSourceEventKind as K;
            let kind = match event.kind {
                K::Open => association::SourceEventKind::Open,
                K::Keepalive => association::SourceEventKind::Keepalive,
                K::Notification => association::SourceEventKind::Notification,
                K::RouteRefresh => association::SourceEventKind::RouteRefresh,
                K::ContinuityGap => association::SourceEventKind::Gap,
                K::GenerationBoundary => association::SourceEventKind::Reset,
                _ => association::SourceEventKind::SourceEvent,
            };
            inspect_borrowed(&event.reference, 3, &mut nodes, limits)?;
            spans = spans
                .checked_add(reference_spans(&event.reference))
                .ok_or_else(|| Error::limit("bgp_persisted_note_spans"))?;
            size = size
                .checked_add(
                    event
                        .reference
                        .encoded_len_bounded(limits.input_bytes)?
                        .saturating_add(4096)
                        .saturating_mul(8),
                )
                .ok_or_else(|| Error::limit("bgp_persisted_source_notes"))?;
            if notes.len() >= limits.elements
                || spans > limits.spans
                || size > limits.retained_bytes
                || size > limits.work
            {
                return Err(Error::limit("bgp_persisted_source_notes"));
            }
            let witness = Json::object([
                ("side", side.into()),
                ("source_store", self.reference()),
                ("note_plane", "source_container_event".into()),
                ("source_event_index", index.into()),
                ("source_record_index", event.source_record_index.into()),
                (
                    "bound_observation_index",
                    event.observation_index.map_or(Json::Null, Json::from),
                ),
                (
                    "context",
                    event.context.as_ref().map_or(Json::Null, |c| c.json()),
                ),
                (
                    "continuity_cuts",
                    Json::array(event.continuity_cuts.iter().map(|cut| {
                        Json::object([
                            ("context", cut.context.json()),
                            ("record_id", cut.record_id.clone().into()),
                            ("reason", cut.reason.clone().into()),
                        ])
                    })),
                ),
                ("source_event", event.reference.clone()),
            ]);
            notes.push(association::SelectionNote::from_source_event(
                kind, &witness, limits,
            )?);
        }
        Ok(notes)
    }
    pub fn associate(
        &self,
        other: &Self,
        namespace: &str,
        policy: &association::Policy,
        limits: &Limits,
    ) -> Result<String> {
        self.associate_impl(other, namespace, policy, limits, false)
    }
    pub fn associate_evidence(
        &self,
        other: &Self,
        namespace: &str,
        policy: &association::Policy,
        limits: &Limits,
    ) -> Result<String> {
        self.associate_impl(other, namespace, policy, limits, true)
    }
    fn associate_impl(
        &self,
        other: &Self,
        namespace: &str,
        policy: &association::Policy,
        limits: &Limits,
        evidence_profile: bool,
    ) -> Result<String> {
        identity(namespace)?;
        limits.validate()?;
        preflight_envelope(self, limits)?;
        preflight_envelope(other, limits)?;
        preflight_association(&self.observations, &other.observations, limits)?;
        if evidence_profile {
            preflight_source_notes(self, other, limits)?;
        }
        let context = association::RouteContext {
            namespace: Some(namespace.into()),
            flow_id: None,
            captured_or_legacy_clock: None,
            coverage: association::Coverage::Unknown,
        };
        let mut routes = Vec::new();
        let mut internal = Vec::new();
        for o in &self.observations {
            for i in 0..o.routes().len() {
                if routes.len() >= limits.elements {
                    return Err(Error::limit("bgp_persisted_association"));
                }
                let mut observation_context = context.clone();
                if o.import_context().is_none() {
                    observation_context.captured_or_legacy_clock =
                        Some(observation_clock(o, &self.namespace));
                }
                routes.push(
                    association::RouteEvidence::from_observation(
                        o,
                        i,
                        &observation_context,
                        limits,
                    )?
                    .with_source_occurrence(&self.occurrence_id(o), limits)?
                    .with_store_selection(
                        self.is_current(o, i),
                        &self.digest,
                        limits,
                    )?,
                );
            }
        }
        for o in &other.observations {
            for (index, r) in o.routes().iter().enumerate() {
                if internal.len() >= limits.elements {
                    return Err(Error::limit("bgp_persisted_association"));
                }
                let c = o.import_context();
                let adapted = association::InternalEvidence::new(
                    association::InternalInput {
                        kind: association::InternalKind::RouteEvidence,
                        source: association::SourceIdentity {
                            source_id: o.source().source_id.clone(),
                            record_id: format!("{}:route:{index}", other.occurrence_id(o)),
                            schema: "pcap-evidence.bgp.persisted-route-projection.v1".into(),
                            version: None,
                            batch: c.map(|c| c.batch.clone()),
                            checkpoint_id: c.map(|c| c.checkpoint_id.clone()),
                        },
                        dimensions: association::Dimensions {
                            scope: association::Scope {
                                namespace: Some(namespace.into()),
                                session: o.source().session.clone(),
                                generation: o.source().generation,
                                flow_id: None,
                                direction: o.source().direction,
                            },
                            prefix: Some(r.prefix().clone()),
                            endpoint: None,
                            unsupported: Vec::new(),
                        },
                        time: association::TimeLabel {
                            observed_at_ns: o.source().observed_at_ns,
                            clock: observation_clock(o, &other.namespace),
                        },
                        coverage: association::Coverage::Unknown,
                        provenance: association::Provenance {
                            record_sha256: Some(sha256::hex(&o.sha256())),
                            ranges: c.map(|c| c.provenance.clone()).unwrap_or_default(),
                            details: Json::object([
                                ("normalized_observation", o.normalized().clone()),
                                ("route_index", index.into()),
                                ("original_record_id", o.source().record_id.clone().into()),
                                ("source_occurrence", other.occurrence_id(o).into()),
                                (
                                    "native_candidate_current",
                                    other.is_current(o, index).into(),
                                ),
                                ("source_store", other.reference()),
                            ]),
                        },
                    },
                    limits,
                )?
                .with_native_disposition(
                    r.action(),
                    other.is_current(o, index),
                    limits,
                )?;
                internal.push(if evidence_profile {
                    adapted.with_semantic_observation(o, index, limits)?
                } else {
                    adapted
                });
            }
        }
        let mut batch = association::RouteBatch::new(routes, limits)?;
        if evidence_profile {
            let mut notes = self.source_notes("left", limits)?;
            notes.extend(other.source_notes("right", limits)?);
            batch = batch.with_source_notes(notes, limits)?;
        }
        let report = if evidence_profile {
            association::associate_evidence(&batch, &internal, policy, limits)?
        } else {
            association::associate(&batch, &internal, policy, limits)?
        };
        bounded_output(
            Json::object([
                (
                    "schema",
                    if evidence_profile {
                        "pcap-evidence.bgp.persisted-association.v2"
                    } else {
                        "pcap-evidence.bgp.persisted-association.v1"
                    }
                    .into(),
                ),
                ("stores", Json::array([self.reference(), other.reference()])),
                ("comparison_namespace", namespace.into()),
                ("association_report", report.to_json()),
                ("occurrences_merged", false.into()),
                ("endpoint_state_claimed", false.into()),
            ]),
            limits,
        )
    }
}
fn reference_spans(v: &Json) -> usize {
    match v {
        Json::Array(a) => a.iter().map(reference_spans).sum(),
        Json::Object(fields) => fields
            .iter()
            .map(|(key, v)| {
                reference_spans(v).saturating_add(
                    if matches!(*key, "spans" | "packets" | "provenance" | "ranges") {
                        if let Json::Array(a) = v {
                            a.len()
                        } else {
                            0
                        }
                    } else {
                        0
                    },
                )
            })
            .sum(),
        _ => 0,
    }
}
fn imported_source_event_charge(
    event: &super::bgp_import::ImportedSourceEvent,
    limits: &Limits,
) -> Result<usize> {
    let mut charge = event
        .reference
        .encoded_len_bounded(limits.input_bytes)?
        .saturating_add(1024)
        .saturating_add(event.source_id.len())
        .saturating_add(event.checkpoint_id.len());
    if event.native_continuity.len() > limits.elements {
        return Err(Error::limit("bgp_persisted_source_events"));
    }
    for effect in &event.native_continuity {
        charge = charge
            .checked_add(effect.retained_charge())
            .ok_or_else(|| Error::limit("bgp_persisted_source_events"))?;
    }
    if let Some(c) = &event.context {
        charge = charge
            .checked_add(c.retained_charge()?)
            .ok_or_else(|| Error::limit("bgp_persisted_source_events"))?;
    }
    for cut in &event.continuity_cuts {
        charge = charge
            .checked_add(
                cut.context
                    .retained_charge()?
                    .saturating_add(cut.record_id.len())
                    .saturating_add(cut.reason.len())
                    .saturating_add(128),
            )
            .ok_or_else(|| Error::limit("bgp_persisted_source_events"))?;
    }
    Ok(charge)
}
// Exact prospective node shape of ImportContext::json for its named v1 schema:
// root and fifteen members, four clock members, three batch members, then
// one object plus three scalar members per ordered source range. No JSON or
// provenance strings are allocated to measure this typed evidence.
fn inspect_context_projection(
    c: &super::bgp_import::ImportContext,
    depth: usize,
    nodes: &mut usize,
    spans: &mut usize,
    limits: &Limits,
) -> Result<()> {
    if c.provenance.len() > limits.elements {
        return Err(Error::limit("bgp_persisted_note_elements"));
    }
    let children = if c.provenance.is_empty() { 2 } else { 3 };
    let deepest = depth
        .checked_add(children)
        .ok_or_else(|| Error::limit("bgp_persisted_depth"))?;
    let count = c
        .provenance
        .len()
        .checked_mul(4)
        .and_then(|v| v.checked_add(23))
        .ok_or_else(|| Error::limit("bgp_persisted_fields"))?;
    admit_note_nodes(count, deepest, nodes, limits)?;
    *spans = spans
        .checked_add(c.provenance.len())
        .ok_or_else(|| Error::limit("bgp_persisted_note_spans"))?;
    if *spans > limits.spans {
        return Err(Error::limit("bgp_persisted_note_spans"));
    }
    Ok(())
}
fn admit_note_nodes(
    count: usize,
    deepest: usize,
    nodes: &mut usize,
    limits: &Limits,
) -> Result<()> {
    if deepest > limits.depth {
        return Err(Error::limit("bgp_persisted_depth"));
    }
    *nodes = nodes
        .checked_add(count)
        .ok_or_else(|| Error::limit("bgp_persisted_fields"))?;
    if *nodes > limits.fields {
        return Err(Error::limit("bgp_persisted_fields"));
    }
    Ok(())
}
fn inspect_source_note_projection(
    receipt: &Json,
    reference: &Json,
    normalized: bool,
    imported: Option<&super::bgp_import::ImportedSourceEvent>,
    nodes: &mut usize,
    spans: &mut usize,
    limits: &Limits,
) -> Result<()> {
    // Final persisted result: report at depth2, note array3, note4, witness5,
    // source_store6/receipt7, and normalized/source/context subtree at depth6.
    // Exact skeleton excludes the borrowed receipt/reference/context/cuts roots.
    admit_note_nodes(
        if normalized || imported.is_some() {
            15
        } else {
            13
        },
        7,
        nodes,
        limits,
    )?;
    inspect_borrowed(receipt, 7, nodes, limits)?;
    inspect_borrowed(reference, 6, nodes, limits)?;
    *spans = spans
        .checked_add(reference_spans(receipt))
        .and_then(|v| v.checked_add(reference_spans(reference)))
        .ok_or_else(|| Error::limit("bgp_persisted_note_spans"))?;
    if let Some(event) = imported {
        if let Some(c) = &event.context {
            inspect_context_projection(c, 6, nodes, spans, limits)?;
        } else {
            admit_note_nodes(1, 6, nodes, limits)?;
        }
        if event.continuity_cuts.len() > limits.elements {
            return Err(Error::limit("bgp_persisted_note_elements"));
        }
        admit_note_nodes(1, 6, nodes, limits)?; // continuity_cuts array
        for cut in &event.continuity_cuts {
            admit_note_nodes(3, 8, nodes, limits)?; // cut object and original ID/reason
            inspect_context_projection(&cut.context, 8, nodes, spans, limits)?;
        }
    }
    if *spans > limits.spans {
        return Err(Error::limit("bgp_persisted_note_spans"));
    }
    Ok(())
}
fn preflight_source_notes(
    left: &VerifiedStore,
    right: &VerifiedStore,
    limits: &Limits,
) -> Result<()> {
    let mut bytes = 0usize;
    let mut nodes = 0usize;
    let mut spans = 0usize;
    let mut count = 0usize;
    admit_note_nodes(1, 3, &mut nodes, limits)?; // final complete selection_notes array
    for store in [left, right] {
        let receipt = store.receipt.encoded_len_bounded(limits.input_bytes)?;
        for o in store.observations.iter().filter(|o| o.routes().is_empty()) {
            count = count
                .checked_add(1)
                .ok_or_else(|| Error::limit("bgp_persisted_notes"))?;
            inspect_source_note_projection(
                &store.receipt,
                o.normalized(),
                true,
                None,
                &mut nodes,
                &mut spans,
                limits,
            )?;
            bytes = bytes
                .checked_add(
                    o.normalized()
                        .encoded_len_bounded(limits.input_bytes)?
                        .saturating_add(receipt)
                        .saturating_add(4096)
                        .saturating_mul(12),
                )
                .ok_or_else(|| Error::limit("bgp_persisted_notes"))?;
        }
        for value in store
            .source_events
            .iter()
            .take(store.captured_source_events.len())
        {
            count = count
                .checked_add(1)
                .ok_or_else(|| Error::limit("bgp_persisted_notes"))?;
            inspect_source_note_projection(
                &store.receipt,
                value,
                false,
                None,
                &mut nodes,
                &mut spans,
                limits,
            )?;
            bytes = bytes
                .checked_add(
                    value
                        .encoded_len_bounded(limits.input_bytes)?
                        .saturating_add(receipt)
                        .saturating_add(4096)
                        .saturating_mul(12),
                )
                .ok_or_else(|| Error::limit("bgp_persisted_notes"))?;
        }
        for event in &store.imported_source_events {
            count = count
                .checked_add(1)
                .ok_or_else(|| Error::limit("bgp_persisted_notes"))?;
            inspect_source_note_projection(
                &store.receipt,
                &event.reference,
                false,
                Some(event),
                &mut nodes,
                &mut spans,
                limits,
            )?;
            bytes = bytes
                .checked_add(
                    imported_source_event_charge(event, limits)?
                        .saturating_add(receipt)
                        .saturating_add(4096)
                        .saturating_mul(12),
                )
                .ok_or_else(|| Error::limit("bgp_persisted_notes"))?;
        }
    }
    if count > limits.elements || bytes > limits.retained_bytes || bytes > limits.work {
        return Err(Error::limit("bgp_persisted_notes"));
    }
    Ok(())
}

fn route_matches_key(route: &super::bgp_state::RouteObservation, key: &RouteKey) -> bool {
    route.prefix() == &key.prefix
        && route.prefix().afi == key.family.afi
        && route.prefix().safi == key.family.safi
        && match (route.path_id(), key.path_id) {
            (super::bgp_state::RoutePathId::Absent, PathId::Absent) => true,
            (super::bgp_state::RoutePathId::Present(a), PathId::Present(b)) => a == b,
            _ => false,
        }
}
fn observation_route_key(
    o: &Observation,
    index: usize,
    namespace: &str,
    limits: &Limits,
) -> Result<RouteKey> {
    let route = o
        .routes()
        .get(index)
        .ok_or_else(|| bad("bgp_persisted_source_route", 0, "route index missing"))?;
    let source = if let Some(c) = o.import_context() {
        super::bgp_session::SourcePartition::from_import_context(c, limits)?
    } else {
        super::bgp_session::SourcePartition {
            kind: PartitionKind::Captured,
            source_id: o.source().source_id.clone(),
            partition_id: namespace.into(),
        }
    };
    Ok(RouteKey {
        scope: super::bgp_rib::RibScope {
            source,
            session: o
                .source()
                .session
                .clone()
                .ok_or_else(|| bad("bgp_persisted_source_route", 0, "session missing"))?,
            generation: o
                .source()
                .generation
                .ok_or_else(|| bad("bgp_persisted_source_route", 0, "generation missing"))?,
            direction: o.source().direction,
            peer: o.source().peer.clone(),
        },
        family: Family {
            afi: route.prefix().afi,
            safi: route.prefix().safi,
        },
        prefix: route.prefix().clone(),
        path_id: match route.path_id() {
            super::bgp_state::RoutePathId::Absent => PathId::Absent,
            super::bgp_state::RoutePathId::Present(v) => PathId::Present(v),
        },
    })
}
fn occurrence_matches(
    entry: &super::bgp_rib::RouteEntry,
    oi: usize,
    o: &Observation,
    captured: Option<&bgp_store::CapturedEntryEvidence>,
    evidence: &[bgp_store::CapturedObservationEvidence],
    namespace: &str,
    limits: &Limits,
) -> Result<bool> {
    let k = &entry.key;
    let source = o.source();
    if source.source_id != k.scope.source.source_id
        || source.session.as_deref() != Some(k.scope.session.as_str())
        || source.generation != Some(k.scope.generation)
        || source.direction != k.scope.direction
        || source.peer != k.scope.peer
    {
        return Ok(false);
    }
    if let Some(e) = captured {
        Ok(k.scope.source.kind == PartitionKind::Captured
            && k.scope.source.partition_id == namespace
            && evidence
                .get(oi)
                .is_some_and(|oe| oe.lifecycle == e.lifecycle))
    } else {
        let Some(context) = o.import_context() else {
            return Ok(false);
        };
        Ok(
            super::bgp_session::SourcePartition::from_import_context(context, limits)?
                == k.scope.source,
        )
    }
}
fn observation_clock(o: &Observation, namespace: &str) -> ObservationClock {
    if let Some(context) = o.import_context() {
        return context.clock.clone();
    }
    if o.source().kind == bgp::SourceKind::Captured && o.source().observed_at_ns.is_some() {
        ObservationClock {
            policy: super::bgp_import::ClockPolicy::SourceLabel,
            clock_id: namespace
                .strip_prefix("capture-namespace-sha256:")
                .map(|v| format!("capture:{v}")),
            reported_uncertainty_ns: None,
        }
    } else {
        ObservationClock::default()
    }
}
fn occurrence_reference(
    o: &Observation,
    index: usize,
    key: &RouteKey,
    capture: Option<&bgp_store::CapturedObservationEvidence>,
    namespace: &str,
    clock: &ObservationClock,
) -> Json {
    let context = o.import_context();
    Json::object([
        (
            "schema",
            "pcap-evidence.bgp.route-occurrence-reference.v1".into(),
        ),
        ("record_id", o.source().record_id.clone().into()),
        (
            "source_occurrence_id",
            observation_occurrence_id(o, capture).into(),
        ),
        (
            "normalized_observation_sha256",
            sha256::hex(&o.sha256()).into(),
        ),
        ("route_index", index.into()),
        (
            "route_key",
            Json::object([
                ("source_id", key.scope.source.source_id.clone().into()),
                ("partition_id", key.scope.source.partition_id.clone().into()),
                (
                    "source_kind",
                    if key.scope.source.kind == PartitionKind::Captured {
                        "captured"
                    } else {
                        "imported"
                    }
                    .into(),
                ),
                ("session", key.scope.session.clone().into()),
                ("generation", key.scope.generation.into()),
                (
                    "direction",
                    key.scope.direction.map_or(Json::Null, Json::from),
                ),
                (
                    "peer",
                    key.scope.peer.clone().map_or(Json::Null, Json::from),
                ),
                ("afi", key.family.afi.into()),
                ("safi", key.family.safi.into()),
                (
                    "prefix",
                    format!("{}/{}", key.prefix.address, key.prefix.length).into(),
                ),
                (
                    "path_id",
                    match key.path_id {
                        PathId::Absent => Json::Null,
                        PathId::Present(n) => n.into(),
                        PathId::Unknown => "unknown".into(),
                    },
                ),
            ]),
        ),
        ("original_namespace", namespace.into()),
        (
            "captured_lifecycle",
            capture.map_or(Json::Null, |e| e.lifecycle.into()),
        ),
        (
            "source_record_index",
            capture.map_or(Json::Null, |e| e.source_record_index.into()),
        ),
        (
            "source_start",
            capture.map_or(Json::Null, |e| e.source_start.into()),
        ),
        (
            "source_end",
            capture.map_or(Json::Null, |e| e.source_end.into()),
        ),
        (
            "journal_record_sha256",
            capture.map_or(Json::Null, |e| sha256::hex(&e.journal_record_sha256).into()),
        ),
        (
            "checkpoint_id",
            context.map_or(Json::Null, |c| c.checkpoint_id.clone().into()),
        ),
        ("clock", clock_json(clock)),
        (
            "observed_at_ns",
            o.source()
                .observed_at_ns
                .map_or(Json::Null, |v| v.to_string().into()),
        ),
        (
            "semantic_identity",
            o.routes()[index].semantic_identity().clone(),
        ),
        (
            "provenance",
            Json::object([
                (
                    "coordinate_system",
                    if context.is_some() {
                        "source_relative"
                    } else {
                        "captured_packet"
                    }
                    .into(),
                ),
                ("import_context", context.map_or(Json::Null, |c| c.json())),
                (
                    "captured_evidence",
                    if context.is_none() {
                        member(o.normalized(), "evidence")
                            .cloned()
                            .unwrap_or(Json::Null)
                    } else {
                        Json::Null
                    },
                ),
            ]),
        ),
        ("normalized_observation", o.normalized().clone()),
    ])
}
fn member<'a>(value: &'a Json, key: &str) -> Option<&'a Json> {
    if let Json::Object(m) = value {
        m.iter().find(|(k, _)| *k == key).map(|(_, v)| v)
    } else {
        None
    }
}
fn number(value: &Json, key: &str) -> Option<u64> {
    match member(value, key) {
        Some(Json::Number(v)) => Some(*v),
        _ => None,
    }
}
fn path_inputs(attributes: &Json) -> (Option<u32>, Option<u32>) {
    let Some(Json::Array(segments)) = member(attributes, "as_path") else {
        return (None, None);
    };
    let mut count = 0u32;
    let mut neighbor = None;
    let mut first_external = true;
    for segment in segments {
        let Some(kind) = number(segment, "kind") else {
            return (None, None);
        };
        let Some(Json::Array(values)) = member(segment, "values") else {
            return (None, None);
        };
        if values
            .iter()
            .any(|v| !matches!(v,Json::Number(n) if *n>0 && *n<=u64::from(u32::MAX)))
        {
            return (None, None);
        };
        match kind {
            1 => {
                let Some(next) = count.checked_add(1) else {
                    return (None, None);
                };
                count = next;
                first_external = false;
            }
            2 => {
                let Some(next) = u32::try_from(values.len())
                    .ok()
                    .and_then(|n| count.checked_add(n))
                else {
                    return (None, None);
                };
                count = next;
                if first_external {
                    neighbor = values.first().and_then(|v| {
                        if let Json::Number(n) = v {
                            Some(*n as u32)
                        } else {
                            None
                        }
                    });
                }
                first_external = false;
            }
            3 | 4 => {}
            _ => return (None, None),
        }
    }
    (Some(count), neighbor)
}
fn status_name(status: RouteStatus) -> &'static str {
    match status {
        RouteStatus::Active => "active",
        RouteStatus::Withdrawn => "withdrawn",
        RouteStatus::Superseded => "superseded",
        RouteStatus::Unresolved => "unresolved",
        RouteStatus::Rejected => "rejected",
        RouteStatus::StaleAtEor => "stale_at_eor",
        RouteStatus::Stale(super::bgp_session::StaleKind::Graceful) => "stale_graceful",
        RouteStatus::Stale(super::bgp_session::StaleKind::LongLivedGraceful) => {
            "stale_long_lived_graceful"
        }
    }
}

fn clock_json(clock: &ObservationClock) -> Json {
    Json::object([
        (
            "policy",
            match clock.policy {
                super::bgp_import::ClockPolicy::Unknown => "unknown",
                super::bgp_import::ClockPolicy::SourceLabel => "source_label",
                super::bgp_import::ClockPolicy::IngestionLabel => "ingestion_label",
            }
            .into(),
        ),
        (
            "clock_id",
            clock.clock_id.clone().map_or(Json::Null, Json::from),
        ),
        (
            "reported_uncertainty_ns",
            clock.reported_uncertainty_ns.map_or(Json::Null, Json::from),
        ),
    ])
}

pub fn bmp_profile(mrt: &MrtLimits) -> bgp_bmp::BmpLimits {
    bgp_bmp::BmpLimits {
        input_bytes: mrt.input_bytes,
        record_bytes: mrt.input_bytes.min(1024 * 1024),
        records: mrt.records,
        peers: mrt.peers,
        tlvs: mrt.rib_entries,
        retained_bytes: mrt.retained_bytes,
        work: mrt.work,
        output_bytes: mrt.output_bytes,
    }
}

fn guard_projection(size: usize, limits: &Limits) -> Result<()> {
    if size > limits.output_bytes
        || size.saturating_mul(3) > limits.retained_bytes
        || size.saturating_mul(2) > limits.work
    {
        return Err(Error::limit("bgp_persisted_projection"));
    }
    Ok(())
}
fn bounded_output(mut value: Json, limits: &Limits) -> Result<String> {
    // Check the entire output, including wrappers, empty arrays and every trace.
    let mut nodes = 0;
    inspect_borrowed(&value, 0, &mut nodes, limits)?;
    if reference_spans(&value) > limits.spans {
        return Err(Error::limit("bgp_persisted_output_spans"));
    }
    canonicalize(&mut value);
    let size = value.encoded_len_bounded(limits.output_bytes.min(limits.retained_bytes))?;
    if size > limits.work {
        return Err(Error::limit("bgp_persisted_output_work"));
    }
    value.encode_bounded(size)
}
fn canonicalize(value: &mut Json) {
    match value {
        Json::Object(fields) => {
            fields.sort_by_key(|(key, _)| *key);
            for (_, v) in fields {
                canonicalize(v)
            }
        }
        Json::Array(values) => {
            for v in values {
                canonicalize(v)
            }
        }
        _ => {}
    }
}
fn inspect_borrowed(value: &Json, depth: usize, nodes: &mut usize, limits: &Limits) -> Result<()> {
    if depth > limits.depth {
        return Err(Error::limit("bgp_persisted_depth"));
    }
    *nodes = nodes
        .checked_add(1)
        .ok_or_else(|| Error::limit("bgp_persisted_fields"))?;
    if *nodes > limits.fields {
        return Err(Error::limit("bgp_persisted_fields"));
    }
    match value {
        Json::Array(values) => {
            if values.len() > limits.elements {
                return Err(Error::limit("bgp_persisted_elements"));
            }
            for v in values {
                inspect_borrowed(v, depth + 1, nodes, limits)?;
            }
        }
        Json::Object(fields) => {
            if fields.len() > limits.fields {
                return Err(Error::limit("bgp_persisted_fields"));
            }
            for (_, v) in fields {
                inspect_borrowed(v, depth + 1, nodes, limits)?;
            }
        }
        _ => {}
    }
    Ok(())
}
fn preflight_output_rows<'a>(
    rows: impl Iterator<Item = &'a RouteRow>,
    limits: &Limits,
    envelope: &Json,
) -> Result<(usize, usize)> {
    let mut sum = 0usize;
    let mut count = 0usize;
    let mut nodes = 0usize;
    inspect_borrowed(envelope, 0, &mut nodes, limits)?;
    for row in rows {
        count += 1;
        if count > limits.elements {
            return Err(Error::limit("bgp_persisted_elements"));
        }
        let size = row.encoded_len(
            limits
                .output_bytes
                .min(limits.retained_bytes)
                .min(limits.work),
        )?;
        inspect_borrowed(&row.alternatives, 3, &mut nodes, limits)?;
        let Json::Object(mut fields) = row.json_projection(false) else {
            unreachable!()
        };
        fields.retain(|(key, _)| *key != "alternatives");
        inspect_borrowed(&Json::Object(fields), 2, &mut nodes, limits)?;
        sum = sum
            .checked_add(size)
            .ok_or_else(|| Error::limit("bgp_persisted_output"))?;
        if sum
            > limits
                .output_bytes
                .min(limits.retained_bytes)
                .min(limits.work)
        {
            return Err(Error::limit("bgp_persisted_output"));
        }
    }
    Ok((sum, nodes))
}
fn preflight_envelope(store: &VerifiedStore, limits: &Limits) -> Result<()> {
    let cap = limits
        .output_bytes
        .min(limits.retained_bytes)
        .min(limits.work);
    let receipt_bytes = store.receipt.encoded_len_bounded(cap)?;
    if receipt_bytes.saturating_mul(3) > limits.retained_bytes {
        return Err(Error::limit("bgp_persisted_envelope"));
    }
    let mut nodes = 0;
    inspect_borrowed(&store.receipt, 2, &mut nodes, limits)?;
    // Scalar wrapper plus borrowed store receipt. Check before cloning receipt.
    if cap < 128 {
        return Err(Error::limit("bgp_persisted_envelope"));
    }
    Ok(())
}
fn preflight_store(store: &VerifiedStore, limits: &Limits) -> Result<()> {
    let mut sum = 0usize;
    for o in &store.observations {
        sum = sum
            .checked_add(
                o.normalized()
                    .encoded_len_bounded(limits.retained_bytes)?
                    .saturating_mul(3),
            )
            .ok_or_else(|| Error::limit("bgp_persisted_retained"))?;
    }
    for occurrence in &store.source_route_occurrences {
        sum = sum
            .checked_add(
                occurrence
                    .occurrence
                    .occurrence_ref
                    .encoded_len_bounded(limits.retained_bytes)?
                    .saturating_mul(6),
            )
            .ok_or_else(|| Error::limit("bgp_persisted_retained"))?;
    }
    for event in &store.captured_source_events {
        sum = sum
            .checked_add(event.retained_charge().saturating_mul(6))
            .ok_or_else(|| Error::limit("bgp_persisted_retained"))?;
    }
    for event in &store.imported_source_events {
        sum = sum
            .checked_add(imported_source_event_charge(event, limits)?.saturating_mul(6))
            .ok_or_else(|| Error::limit("bgp_persisted_retained"))?;
    }
    for event in &store.source_events {
        sum = sum
            .checked_add(
                event
                    .encoded_len_bounded(limits.retained_bytes)?
                    .saturating_mul(6),
            )
            .ok_or_else(|| Error::limit("bgp_persisted_retained"))?;
    }
    for row in &store.rows {
        sum = sum
            .checked_add(
                row.version_occurrences
                    .encoded_len_bounded(limits.retained_bytes)?
                    .saturating_mul(6),
            )
            .ok_or_else(|| Error::limit("bgp_persisted_retained"))?;
        sum = sum
            .checked_add(row.encoded_len(limits.retained_bytes)?.saturating_mul(3))
            .ok_or_else(|| Error::limit("bgp_persisted_retained"))?;
    }
    if sum > limits.retained_bytes || sum > limits.work {
        return Err(Error::limit("bgp_persisted_retained"));
    }
    Ok(())
}
fn preflight_association(
    left: &[Observation],
    right: &[Observation],
    limits: &Limits,
) -> Result<()> {
    let mut sum = 0usize;
    let mut counts = [0usize; 2];
    for (side, observations) in [left, right].into_iter().enumerate() {
        for o in observations {
            counts[side] = counts[side]
                .checked_add(o.routes().len())
                .ok_or_else(|| Error::limit("bgp_persisted_association"))?;
            let size = o.normalized().encoded_len_bounded(limits.input_bytes)?;
            let charge = size
                .checked_add(1024)
                .and_then(|n| n.checked_mul(o.routes().len()))
                .and_then(|n| n.checked_mul(8))
                .ok_or_else(|| Error::limit("bgp_persisted_association"))?;
            sum = sum
                .checked_add(charge)
                .ok_or_else(|| Error::limit("bgp_persisted_association"))?;
        }
    }
    if counts[0].saturating_add(counts[1]) > limits.elements
        || counts[0].saturating_mul(counts[1]) > limits.elements
        || sum > limits.retained_bytes
        || sum > limits.work
    {
        return Err(Error::limit("bgp_persisted_association"));
    }
    Ok(())
}

fn entry_charge(entry: &super::bgp_rib::RouteEntry, limits: &Limits) -> Result<usize> {
    let mut size = entry
        .key
        .scope
        .source
        .source_id
        .len()
        .saturating_add(entry.key.scope.source.partition_id.len())
        .saturating_add(entry.key.scope.session.len())
        .saturating_add(entry.key.scope.peer.as_ref().map_or(0, String::len))
        .saturating_add(entry.key.prefix.address.len())
        .saturating_add(entry.last_witness.len())
        .saturating_add(1024);
    for v in &entry.versions {
        size = size
            .checked_add(v.attributes.encoded_len_bounded(limits.retained_bytes)?)
            .and_then(|n| n.checked_add(v.attribute_identity.len()))
            .and_then(|n| {
                v.occurrences
                    .len()
                    .checked_mul(128)
                    .and_then(|charge| n.checked_add(charge))
            })
            .and_then(|n| {
                n.checked_add(
                    v.witnesses
                        .iter()
                        .map(|s| s.len().saturating_add(32))
                        .sum::<usize>(),
                )
            })
            .ok_or_else(|| Error::limit("bgp_persisted_clone"))?;
    }
    Ok(size)
}
fn observation_occurrence_id(
    observation: &Observation,
    captured: Option<&bgp_store::CapturedObservationEvidence>,
) -> String {
    match captured {
        Some(e) => format!(
            "captured-lifecycle:{}:record:{}:observation:{}",
            e.lifecycle,
            sha256::hex(&e.journal_record_sha256),
            sha256::hex(&observation.sha256())
        ),
        None => format!("observation:{}", sha256::hex(&observation.sha256())),
    }
}

fn preflight_native_clone(
    rib: &super::bgp_rib::AdjRibIn,
    observations: &[Observation],
    limits: &Limits,
) -> Result<()> {
    let mut charge = 0usize;
    if rib.entries().len().saturating_add(rib.rejections().len()) > limits.elements {
        return Err(Error::limit("bgp_persisted_routes"));
    }
    for entry in rib.entries().values() {
        charge = charge
            .checked_add(entry_charge(entry, limits)?.saturating_mul(6))
            .ok_or_else(|| Error::limit("bgp_persisted_clone"))?;
    }
    for o in observations {
        charge = charge
            .checked_add(
                o.normalized()
                    .encoded_len_bounded(limits.retained_bytes)?
                    .saturating_mul(6),
            )
            .ok_or_else(|| Error::limit("bgp_persisted_clone"))?;
    }
    for rejection in rib.rejections() {
        charge = charge
            .checked_add(rejection_charge(rejection).saturating_mul(8))
            .ok_or_else(|| Error::limit("bgp_persisted_clone"))?;
    }
    if charge > limits.retained_bytes || charge > limits.work {
        return Err(Error::limit("bgp_persisted_clone"));
    }
    Ok(())
}

fn rejection_charge(rejection: &super::bgp_rib::RejectedRecord) -> usize {
    rejection
        .key
        .scope
        .source
        .source_id
        .len()
        .saturating_add(rejection.key.scope.source.partition_id.len())
        .saturating_add(rejection.key.scope.session.len())
        .saturating_add(rejection.key.scope.peer.as_ref().map_or(0, String::len))
        .saturating_add(rejection.key.prefix.address.len())
        .saturating_add(rejection.record_id.len())
        .saturating_add(rejection.reason.len())
        .saturating_add(2048)
}

// Ended captured lifecycles suppress historical activity while keeping the
// native reducer's typed exclusion reason for every nonactive status.
fn policy_native_status(status: RouteStatus, current: bool) -> RouteStatus {
    if status == RouteStatus::Active && !current {
        RouteStatus::Unresolved
    } else {
        status
    }
}

#[cfg(test)]
mod persisted_status_tests {
    use super::*;
    #[test]
    fn policy_preserves_all_native_exclusion_statuses_across_lifecycle_suppression() {
        use super::super::bgp_session::StaleKind;
        for status in [
            RouteStatus::Withdrawn,
            RouteStatus::Superseded,
            RouteStatus::Stale(StaleKind::Graceful),
            RouteStatus::Stale(StaleKind::LongLivedGraceful),
            RouteStatus::StaleAtEor,
            RouteStatus::Rejected,
            RouteStatus::Unresolved,
        ] {
            assert_eq!(policy_native_status(status, false), status);
            assert_eq!(policy_native_status(status, true), status);
        }
        assert_eq!(
            policy_native_status(RouteStatus::Active, false),
            RouteStatus::Unresolved
        );
        assert_eq!(
            policy_native_status(RouteStatus::Active, true),
            RouteStatus::Active
        );
    }
}

#[cfg(test)]
mod prospective_note_tests {
    use super::super::bgp_import::{
        ImportContext, ImportContinuityCut, ImportedSourceEvent, ImportedSourceEventKind,
        SourceBatch, SourceRange,
    };
    use super::*;
    fn source(events: Vec<ImportedSourceEvent>) -> VerifiedStore {
        VerifiedStore {
            receipt: super::super::bgp_bmp_store::BmpStoreReceipt {
                source_id: "typed-budget-source".into(),
                checkpoint_id: "checkpoint".into(),
                source_sha256: [1; 32],
                source_bytes: 100,
                terminal_sha256: [2; 32],
                records: 2,
            }
            .json(),
            digest: sha256::hex(&[2; 32]),
            namespace: "typed-budget-source".into(),
            rows: Vec::new(),
            observations: Vec::new(),
            captured_observation_evidence: Vec::new(),
            peer_relationship: None,
            source_events: Vec::new(),
            captured_source_events: Vec::new(),
            imported_source_events: events,
            source_route_occurrences: Vec::new(),
        }
    }
    #[test]
    fn full_note_shape_is_admitted_exactly_before_copy_with_one_below_controls() {
        // This is a prospective shape/budget control. Sealed semantic source
        // witnesses are owned by the BMP/capture integration tests.
        let context = ImportContext {
            source_id: "typed-budget-source".into(),
            source_schema: "pcap-evidence.bgp.bmp-normalized.v1".into(),
            source_version: Some("3".into()),
            clock: ObservationClock::default(),
            batch: SourceBatch {
                batch_id: Some("immutable-batch".into()),
                sha256: None,
                byte_length: Some(100),
            },
            checkpoint_id: "checkpoint".into(),
            session: "peer-1".into(),
            generation: 0,
            direction: Some(0),
            peer: Some("192.0.2.1".into()),
            local: None,
            provenance: vec![
                SourceRange {
                    start: 0,
                    end: 10,
                    sha256: None,
                },
                SourceRange {
                    start: 10,
                    end: 20,
                    sha256: None,
                },
            ],
        };
        let high = Limits {
            fields: 65536,
            work: 32 * 1024 * 1024,
            retained_bytes: 32 * 1024 * 1024,
            ..Limits::default()
        };
        context.validate(&high).unwrap();
        let events = (0..2)
            .map(|index| ImportedSourceEvent {
                source_id: context.source_id.clone(),
                checkpoint_id: context.checkpoint_id.clone(),
                native_continuity: Vec::new(),
                source_record_index: index,
                observation_index: None,
                kind: ImportedSourceEventKind::SessionMetadata,
                context: Some(context.clone()),
                continuity_cuts: vec![ImportContinuityCut {
                    context: context.clone(),
                    record_id: format!("cut:{index}"),
                    reason: "original-container-rejection".into(),
                }],
                reference: Json::object([("source_record_index", index.into())]),
            })
            .collect();
        let left = source(events);
        let right = source(Vec::new());
        let notes = left.source_notes("left", &high).unwrap();
        let projected = Json::array(notes.iter().map(|n| {
            Json::object([
                ("reason", n.reason().name().into()),
                (
                    "source_event_kind",
                    n.source_event_kind().unwrap().name().into(),
                ),
                ("witness", n.witness().clone()),
            ])
        }));
        let mut exact_nodes = 0;
        inspect_borrowed(&projected, 3, &mut exact_nodes, &high).unwrap();
        let exact_spans = reference_spans(&projected);
        let mut exact = high.clone();
        exact.fields = exact_nodes;
        exact.depth = 11;
        exact.spans = exact_spans;
        preflight_source_notes(&left, &right, &exact).unwrap();
        exact.fields -= 1;
        assert!(preflight_source_notes(&left, &right, &exact).is_err());
        exact.fields = exact_nodes;
        exact.depth -= 1;
        assert!(preflight_source_notes(&left, &right, &exact).is_err());
        exact.depth = 11;
        exact.spans -= 1;
        assert!(preflight_source_notes(&left, &right, &exact).is_err());
        assert!(notes.iter().all(|n| {
            let mut nodes = 0;
            inspect_borrowed(n.witness(), 1, &mut nodes, &high).unwrap();
            nodes < exact_nodes - 1
        }));
    }
}
