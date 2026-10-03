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

#[derive(Clone, Debug, Default)]
pub struct Query {
    pub session: Option<String>,
    pub prefix: Option<String>,
    pub afi: Option<u16>,
    pub safi: Option<u8>,
    pub peer: Option<String>,
    pub source: Option<String>,
    pub checkpoint: Option<String>,
    pub status: Option<String>,
}
impl Query {
    pub fn validate(&self) -> Result<()> {
        for v in [
            &self.session,
            &self.prefix,
            &self.peer,
            &self.source,
            &self.checkpoint,
            &self.status,
        ]
        .into_iter()
        .flatten()
        {
            identity(v)?;
        }
        if self.afi == Some(0) || self.safi == Some(0) {
            return Err(bad("bgp_query_family", 0, "nonzero family required"));
        }
        if let Some(status) = &self.status {
            if !matches!(
                status.as_str(),
                "active"
                    | "withdrawn"
                    | "superseded"
                    | "unresolved"
                    | "rejected"
                    | "stale_graceful"
                    | "stale_long_lived_graceful"
                    | "stale_at_eor"
                    | "collector_candidate"
            ) {
                return Err(bad("bgp_query_status", 0, "unknown status"));
            }
        }
        if let Some(prefix) = &self.prefix {
            let (address, length) = prefix
                .rsplit_once('/')
                .ok_or_else(|| bad("bgp_query_prefix", 0, "CIDR required"))?;
            let ip: IpAddr = address
                .parse()
                .map_err(|_| bad("bgp_query_prefix", 0, "invalid IP"))?;
            let len: u8 = length
                .parse()
                .map_err(|_| bad("bgp_query_prefix", 0, "invalid length"))?;
            let max = if ip.is_ipv4() { 32 } else { 128 };
            if ip.to_string() != address || len > max || len.to_string() != length {
                return Err(bad("bgp_query_prefix", 0, "canonical CIDR required"));
            }
            let host_bits = match ip {
                IpAddr::V4(value) => {
                    let mask = if len == 0 { 0 } else { u32::MAX << (32 - len) };
                    u32::from(value) & !mask != 0
                }
                IpAddr::V6(value) => {
                    let mask = if len == 0 {
                        0
                    } else {
                        u128::MAX << (128 - len)
                    };
                    u128::from(value) & !mask != 0
                }
            };
            if host_bits {
                return Err(bad("bgp_query_prefix", 0, "canonical network required"));
            }
        }
        Ok(())
    }
    fn matches(&self, row: &RouteRow) -> bool {
        let k = &row.key;
        self.session.as_ref().is_none_or(|v| v == &k.scope.session)
            && self
                .prefix
                .as_ref()
                .is_none_or(|v| v == &format!("{}/{}", k.prefix.address, k.prefix.length))
            && self.afi.is_none_or(|v| v == k.family.afi)
            && self.safi.is_none_or(|v| v == k.family.safi)
            && self
                .peer
                .as_ref()
                .is_none_or(|v| Some(v) == k.scope.peer.as_ref())
            && self
                .source
                .as_ref()
                .is_none_or(|v| v == &k.scope.source.source_id)
            && self
                .checkpoint
                .as_ref()
                .is_none_or(|v| Some(v) == row.checkpoint.as_ref())
            && self.status.as_ref().is_none_or(|v| v == row.status_name())
    }
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
    attributes: Option<Json>,
    witnesses: Vec<String>,
    checkpoint: Option<String>,
    clock: ObservationClock,
    observed_at_ns: Option<i64>,
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
        let mut captured_entry_evidence = Vec::new();
        let mut captured_observation_evidence = Vec::new();
        let (receipt, digest, namespace, entries, observations, collector) =
            if &magic == bgp_store::MAGIC {
                if options.peer_relationship.is_some() {
                    return Err(bad(
                        "bgp_persisted_options",
                        0,
                        "capture replay does not accept imported relationship override",
                    ));
                }
                let a = bgp_store::replay(path, maximum, limits.clone())?;
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
                        attributes: None,
                        witnesses: vec![c.record_id.clone()],
                        checkpoint: Some(c.checkpoint_id.clone()),
                        clock: o.import_context().expect("checked context").clock.clone(),
                        observed_at_ns: c.observed_at_ns,
                    });
                }
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
            let observation = observations
                .iter()
                .enumerate()
                .rev()
                .find(|(oi, o)| {
                    capture_evidence.is_none_or(|e| {
                        captured_observation_evidence
                            .get(*oi)
                            .is_some_and(|oe| oe.lifecycle == e.lifecycle)
                    }) && o.source().source_id == entry.key.scope.source.source_id
                        && o.source().session.as_deref() == Some(&entry.key.scope.session)
                        && o.source().record_id == entry.last_witness
                })
                .map(|(_, o)| o);
            let context = observation.and_then(Observation::import_context);
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
            let witnesses = if let Some(e) = capture_evidence {
                e.observation_sha256
                    .iter()
                    .map(|v| sha256::hex(v))
                    .collect()
            } else {
                versions
                    .iter()
                    .flat_map(|v| v.witnesses.iter())
                    .filter_map(|id| {
                        observations
                            .iter()
                            .rev()
                            .find(|o| o.source().record_id == *id)
                            .map(|o| sha256::hex(&o.sha256()))
                    })
                    .collect()
            };
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
                attributes: if versions.len() == 1 {
                    Some(versions[0].attributes.clone())
                } else {
                    None
                },
                witnesses,
                checkpoint: context.map(|c| c.checkpoint_id.clone()),
                clock: context.map(|c| c.clock.clone()).unwrap_or_default(),
                observed_at_ns: observation.and_then(|o| o.source().observed_at_ns),
            });
        }
        let result = Self {
            receipt,
            digest,
            namespace,
            rows,
            observations,
            captured_observation_evidence,
            peer_relationship: options.peer_relationship,
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
        match life {
            Some(e) => format!(
                "captured-lifecycle:{}:record:{}:observation:{}",
                e.lifecycle,
                sha256::hex(&e.journal_record_sha256),
                sha256::hex(&o.sha256())
            ),
            None => format!("observation:{}", sha256::hex(&o.sha256())),
        }
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
        limits.validate()?;
        preflight_envelope(self, limits)?;
        let empty = Json::object([
            ("schema", "pcap-evidence.bgp.persisted-query.v1".into()),
            ("store", self.reference()),
            ("routes", Json::array([])),
            ("endpoint_state_claimed", false.into()),
        ]);
        let (row_bytes, _) = preflight_output_rows(
            self.rows.iter().filter(|r| query.matches(r)),
            limits,
            &empty,
        )?;
        let empty = empty.encoded_len_bounded(limits.output_bytes)?;
        let count = self.rows.iter().filter(|r| query.matches(r)).count();
        guard_projection(
            empty
                .saturating_add(row_bytes)
                .saturating_add(count.saturating_sub(1)),
            limits,
        )?;
        let rows = Json::array(
            self.rows
                .iter()
                .filter(|r| query.matches(r))
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
    pub fn policy(
        &self,
        query: &Query,
        profile: &PolicyProfile,
        limits: &Limits,
    ) -> Result<String> {
        query.validate()?;
        limits.validate()?;
        preflight_envelope(self, limits)?;
        let envelope = Json::object([
            (
                "schema",
                "pcap-evidence.bgp.persisted-policy-result.v1".into(),
            ),
            ("store", self.reference()),
            ("policy_results", Json::array([])),
            ("alternatives", Json::array([])),
            ("endpoint_state_claimed", false.into()),
        ]);
        let (row_bytes, mut output_nodes) = preflight_output_rows(
            self.rows.iter().filter(|r| query.matches(r)),
            limits,
            &envelope,
        )?;
        let envelope_bytes = envelope.encoded_len_bounded(limits.output_bytes)?;
        let row_count = self.rows.iter().filter(|r| query.matches(r)).count();
        guard_projection(
            envelope_bytes
                .saturating_add(row_bytes)
                .saturating_add(row_count.saturating_sub(1)),
            limits,
        )?;
        let mut groups: BTreeMap<NativePolicyScope, Vec<PolicyCandidate>> = BTreeMap::new();
        for row in self.rows.iter().filter(|r| query.matches(r)) {
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
                    status: if row.current {
                        row.status
                    } else {
                        RouteStatus::Unresolved
                    },
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
        bounded_output(
            Json::object([
                (
                    "schema",
                    "pcap-evidence.bgp.persisted-policy-result.v1".into(),
                ),
                ("store", self.reference()),
                ("policy_results", Json::array(encoded)),
                (
                    "alternatives",
                    Json::array(
                        self.rows
                            .iter()
                            .filter(|r| query.matches(r))
                            .map(RouteRow::json),
                    ),
                ),
                ("endpoint_state_claimed", false.into()),
            ]),
            limits,
        )
    }
    pub fn associate(
        &self,
        other: &Self,
        namespace: &str,
        policy: &association::Policy,
        limits: &Limits,
    ) -> Result<String> {
        identity(namespace)?;
        limits.validate()?;
        preflight_envelope(self, limits)?;
        preflight_envelope(other, limits)?;
        preflight_association(&self.observations, &other.observations, limits)?;
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
                routes.push(
                    association::RouteEvidence::from_observation(o, i, &context, limits)?
                        .with_source_occurrence(&self.occurrence_id(o), limits)?
                        .with_store_selection(self.is_current(o, i), &self.digest, limits)?,
                );
            }
        }
        for o in &other.observations {
            for (index, r) in o.routes().iter().enumerate() {
                if internal.len() >= limits.elements {
                    return Err(Error::limit("bgp_persisted_association"));
                }
                let c = o.import_context();
                internal.push(
                    association::InternalEvidence::new(
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
                                clock: c.map(|c| c.clock.clone()).unwrap_or_default(),
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
                    )?,
                );
            }
        }
        let batch = association::RouteBatch::new(routes, limits)?;
        let report = association::associate(&batch, &internal, policy, limits)?;
        bounded_output(
            Json::object([
                (
                    "schema",
                    "pcap-evidence.bgp.persisted-association.v1".into(),
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
    for row in &store.rows {
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
fn preflight_native_clone(
    rib: &super::bgp_rib::AdjRibIn,
    observations: &[Observation],
    limits: &Limits,
) -> Result<()> {
    let mut charge = 0usize;
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
    if charge > limits.retained_bytes || charge > limits.work {
        return Err(Error::limit("bgp_persisted_clone"));
    }
    Ok(())
}
