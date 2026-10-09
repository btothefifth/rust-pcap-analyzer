//! Bounded source-occurrence analysis. Caller expectations are assertions,
//! never authentication, route installation, or source-coverage certification.
use super::query::{AsnRole, AsnSelector, AttributeMatch};
use super::*;
use crate::deep::bgp_state::{ObservationKind, RouteObservation, RoutePathId};

pub const EXPECTATION_PROFILE_SCHEMA: &str = "pcap-evidence.bgp.expectation-profile.v1";
pub const EXPECTATION_PROFILE_SCHEMA_V2: &str = "pcap-evidence.bgp.expectation-profile.v2";
pub const EXPECTATION_RESULT_SCHEMA: &str = "pcap-evidence.bgp.expectations.v1";
pub const CHANGES_SCHEMA: &str = "pcap-evidence.bgp.changes.v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoverageDeclaration {
    Unknown,
    CallerDeclaredComplete,
}
impl CoverageDeclaration {
    fn name(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::CallerDeclaredComplete => "caller_declared_complete",
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExpectedPresence {
    Present,
    Absent,
}
#[derive(Clone, Debug)]
pub struct Expectation {
    id: String,
    presence: ExpectedPresence,
    declaration: String,
    query: Query,
    // Option::None means exact native absence, never a wildcard.
    direction: Option<u8>,
    peer: Option<String>,
    checkpoint: Option<String>,
    lifecycle: Option<u64>,
}
#[derive(Clone, Debug)]
pub struct ExpectationProfile {
    schema: &'static str,
    provenance: String,
    coverage: CoverageDeclaration,
    expectations: Vec<Expectation>,
    profile_sha256: String,
}
impl ExpectationProfile {
    /// Strict UTF-8 LF `key=value` profile. Required headers appear exactly once.
    /// Each expectation has nineteen exact fields; see the shipped contract.
    pub fn parse(bytes: &[u8], limits: &Limits) -> Result<Self> {
        limits.validate()?;
        if bytes.is_empty()
            || bytes.len()
                > MAX_PROFILE_BYTES
                    .min(limits.input_bytes)
                    .min(limits.retained_bytes)
                    .min(limits.work)
        {
            return Err(Error::limit("bgp_expectation_profile"));
        }
        let text = std::str::from_utf8(bytes)
            .map_err(|_| bad("bgp_expectation_profile", 0, "UTF-8 LF required"))?;
        // Admit the complete profile's bounded parse allocations before copying.
        let estimated = bytes
            .len()
            .checked_mul(6)
            .and_then(|n| n.checked_add(4096))
            .ok_or_else(|| Error::limit("bgp_expectation_profile"))?;
        if estimated > limits.retained_bytes || estimated > limits.work {
            return Err(Error::limit("bgp_expectation_profile"));
        }
        let mut headers = BTreeMap::new();
        let mut raw_rows = Vec::new();
        for line in text.strip_suffix('\n').unwrap_or(text).split('\n') {
            let (key, value) = line
                .split_once('=')
                .ok_or_else(|| bad("bgp_expectation_profile", 0, "key=value required"))?;
            if value.is_empty() || value.trim() != value || value.chars().any(char::is_control) {
                return Err(bad(
                    "bgp_expectation_profile",
                    0,
                    "exact nonempty LF values required",
                ));
            }
            if key == "expectation" {
                if raw_rows.len() >= limits.elements.min(256) {
                    return Err(Error::limit("bgp_expectation_rows"));
                }
                raw_rows.push(value);
            } else if matches!(key, "schema" | "provenance" | "time_basis" | "coverage") {
                if headers.insert(key, value).is_some() {
                    return Err(bad("bgp_expectation_profile", 0, "duplicate header"));
                }
            } else {
                return Err(bad("bgp_expectation_profile", 0, "unknown key"));
            }
        }
        let required = |key| {
            headers
                .get(key)
                .copied()
                .ok_or_else(|| bad("bgp_expectation_profile", 0, "required header missing"))
        };
        let schema = match required("schema")? {
            EXPECTATION_PROFILE_SCHEMA => EXPECTATION_PROFILE_SCHEMA,
            EXPECTATION_PROFILE_SCHEMA_V2 => EXPECTATION_PROFILE_SCHEMA_V2,
            _ => {
                return Err(Error::new(
                    ErrorCode::UnsupportedVersion,
                    0,
                    "bgp_expectation_profile",
                    "unsupported schema",
                ))
            }
        };
        let mut rows = Vec::new();
        let mut ids = BTreeSet::new();
        for value in raw_rows {
            let row = parse_expectation(value, schema == EXPECTATION_PROFILE_SCHEMA_V2)?;
            if !ids.insert(row.id.clone()) {
                return Err(bad(
                    "bgp_expectation_profile",
                    0,
                    "duplicate expectation ID",
                ));
            }
            rows.push(row);
        }
        let provenance = required("provenance")?;
        identity(provenance)?;
        if required("time_basis")? != "source_occurrence_order" {
            return Err(bad(
                "bgp_expectation_profile",
                0,
                "source_occurrence_order required",
            ));
        }
        let coverage = match required("coverage")? {
            "unknown" => CoverageDeclaration::Unknown,
            "caller_declared_complete" => CoverageDeclaration::CallerDeclaredComplete,
            _ => {
                return Err(bad(
                    "bgp_expectation_profile",
                    0,
                    "invalid explicit coverage",
                ))
            }
        };
        if rows.is_empty() {
            return Err(bad(
                "bgp_expectation_profile",
                0,
                "at least one expectation required",
            ));
        }
        Ok(Self {
            schema,
            provenance: provenance.into(),
            coverage,
            expectations: rows,
            profile_sha256: sha256::hex(&sha256::digest(bytes)),
        })
    }
    pub fn read(path: &Path, limits: &Limits) -> Result<Self> {
        limits.validate()?;
        let file = File::open(path)?;
        let metadata = file.metadata()?;
        let bytes =
            usize::try_from(metadata.len()).map_err(|_| Error::limit("bgp_expectation_profile"))?;
        let charge = bytes
            .checked_mul(6)
            .and_then(|n| n.checked_add(4096))
            .ok_or_else(|| Error::limit("bgp_expectation_profile"))?;
        if !metadata.is_file()
            || bytes > MAX_PROFILE_BYTES.min(limits.input_bytes)
            || charge > limits.retained_bytes
            || charge > limits.work
        {
            return Err(Error::limit("bgp_expectation_profile"));
        }
        drop(file);
        // The reader also bounds a concurrent file growth; parse re-admits final bytes.
        let allocation_cap = limits.retained_bytes.min(limits.work).saturating_sub(4096) / 6;
        Self::parse(
            &bounded_read(
                path,
                MAX_PROFILE_BYTES
                    .min(limits.input_bytes)
                    .min(allocation_cap) as u64,
            )?,
            limits,
        )
    }
}
fn canonical_u64(value: &str) -> Result<u64> {
    if value.is_empty()
        || !value.bytes().all(|b| b.is_ascii_digit())
        || value.len() > 1 && value.starts_with('0')
    {
        return Err(bad(
            "bgp_expectation_profile",
            0,
            "canonical unsigned integer required",
        ));
    }
    value
        .parse()
        .map_err(|_| bad("bgp_expectation_profile", 0, "integer out of range"))
}
fn exact_optional_text(value: &str, v2: bool) -> Result<Option<String>> {
    if !v2 {
        if value == "absent" {
            return Ok(None);
        }
        identity(value)?;
        return Ok(Some(value.into()));
    }
    if value == "none" {
        return Ok(None);
    }
    let encoded = value.strip_prefix("text:").ok_or_else(|| {
        bad(
            "bgp_expectation_profile",
            0,
            "none or text:encoded optional text required",
        )
    })?;
    let mut decoded = Vec::new();
    let mut bytes = encoded.bytes();
    while let Some(byte) = bytes.next() {
        let decoded_byte = if byte == b'%' {
            let hex = |b: u8| match b {
                b'0'..=b'9' => Some(b - b'0'),
                b'A'..=b'F' => Some(b - b'A' + 10),
                _ => None,
            };
            let high = bytes.next().and_then(hex);
            let low = bytes.next().and_then(hex);
            let (Some(high), Some(low)) = (high, low) else {
                return Err(bad(
                    "bgp_expectation_profile",
                    0,
                    "uppercase percent escape required",
                ));
            };
            let b = high * 16 + low;
            if optional_text_unreserved(b) {
                return Err(bad(
                    "bgp_expectation_profile",
                    0,
                    "unreserved bytes must be literal",
                ));
            }
            b
        } else {
            if !optional_text_unreserved(byte) {
                return Err(bad(
                    "bgp_expectation_profile",
                    0,
                    "non-unreserved bytes require percent escape",
                ));
            }
            byte
        };
        if decoded.len() >= 1024 {
            return Err(bad(
                "bgp_expectation_profile",
                0,
                "bounded decoded identity required",
            ));
        }
        decoded.push(decoded_byte);
    }
    let text = String::from_utf8(decoded)
        .map_err(|_| bad("bgp_expectation_profile", 0, "UTF-8 optional text required"))?;
    native_optional_identity(&text)?;
    Ok(Some(text))
}
fn optional_text_unreserved(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~')
}
fn exact_optional_u64(value: &str) -> Result<Option<u64>> {
    if value == "absent" {
        Ok(None)
    } else {
        canonical_u64(value).map(Some)
    }
}
fn parse_expectation(value: &str, v2: bool) -> Result<Expectation> {
    let f: Vec<_> = value.split('|').collect();
    if f.len() != 19
        || f.iter().enumerate().any(|(i, v)| {
            v.is_empty()
                || v.trim() != *v
                || v.len()
                    > if v2 && matches!(i, 2 | 4 | 7 | 8) {
                        5 + 3 * 1024
                    } else {
                        1024
                    }
        })
    {
        return Err(bad(
            "bgp_expectation_profile",
            0,
            "nineteen bounded exact fields required",
        ));
    }
    for i in [0, 3] {
        identity(f[i])?;
    }
    let required_text = |value: &str| -> Result<String> {
        exact_optional_text(value, v2)?.ok_or_else(|| {
            bad(
                "bgp_expectation_profile",
                0,
                "present source/session text required",
            )
        })
    };
    let source = if v2 {
        required_text(f[2])?
    } else {
        identity(f[2])?;
        f[2].into()
    };
    let session = if v2 {
        required_text(f[4])?
    } else {
        identity(f[4])?;
        f[4].into()
    };
    let presence = match f[1] {
        "present" => ExpectedPresence::Present,
        "absent" => ExpectedPresence::Absent,
        _ => {
            return Err(bad(
                "bgp_expectation_profile",
                0,
                "present or absent required",
            ))
        }
    };
    let direction = exact_optional_u64(f[6])?
        .map(|v| {
            u8::try_from(v).map_err(|_| bad("bgp_expectation_profile", 0, "direction out of range"))
        })
        .transpose()?;
    let peer = exact_optional_text(f[7], v2)?;
    let checkpoint = exact_optional_text(f[8], v2)?;
    let lifecycle = exact_optional_u64(f[9])?;
    if let Some(life) = lifecycle {
        if !f[3].ends_with(&format!(":captured-lifecycle:{life}")) {
            return Err(bad(
                "bgp_expectation_profile",
                0,
                "captured partition must carry exact lifecycle",
            ));
        }
    }
    // Exact native partition cannot mix capture lifecycle with import checkpoint.
    if checkpoint.is_some() == lifecycle.is_some() {
        return Err(bad(
            "bgp_expectation_profile",
            0,
            "exact capture lifecycle or import checkpoint required",
        ));
    }
    let afi = u16::try_from(canonical_u64(f[10])?)
        .map_err(|_| bad("bgp_expectation_profile", 0, "AFI out of range"))?;
    let safi = u8::try_from(canonical_u64(f[11])?)
        .map_err(|_| bad("bgp_expectation_profile", 0, "SAFI out of range"))?;
    let path_id = if f[13] == "absent" {
        PathId::Absent
    } else {
        PathId::Present(
            u32::try_from(canonical_u64(f[13])?)
                .map_err(|_| bad("bgp_expectation_profile", 0, "path ID out of range"))?,
        )
    };
    let asn = if f[14] == "unknown" {
        None
    } else {
        let (role, number) = f[14]
            .split_once(':')
            .ok_or_else(|| bad("bgp_expectation_profile", 0, "ASN role:number required"))?;
        Some(AsnSelector {
            role: match role {
                "origin" => AsnRole::Origin,
                "path_member" => AsnRole::PathMember,
                _ => return Err(bad("bgp_expectation_profile", 0, "invalid ASN role")),
            },
            asn: optional_u32(number)?
                .ok_or_else(|| bad("bgp_expectation_profile", 0, "ASN required"))?,
        })
    };
    let large_community = if f[16] == "unknown" {
        None
    } else {
        let v: Vec<_> = f[16].split(':').collect();
        if v.len() != 3 {
            return Err(bad(
                "bgp_expectation_profile",
                0,
                "three community integers required",
            ));
        }
        Some([parse_u32(v[0])?, parse_u32(v[1])?, parse_u32(v[2])?])
    };
    let extended_community = if f[17] == "unknown" {
        None
    } else {
        if f[17].len() != 16
            || !f[17]
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(bad(
                "bgp_expectation_profile",
                0,
                "sixteen lowercase hex digits required",
            ));
        }
        let mut a = [0u8; 8];
        for (i, b) in a.iter_mut().enumerate() {
            *b = u8::from_str_radix(&f[17][2 * i..2 * i + 2], 16)
                .map_err(|_| bad("bgp_expectation_profile", 0, "invalid extended community"))?;
        }
        Some(a)
    };
    let query = Query {
        source: Some(source),
        partition: Some(f[3].into()),
        session: Some(session),
        generation: Some(canonical_u64(f[5])?),
        direction,
        peer: peer.clone(),
        checkpoint: checkpoint.clone(),
        lifecycle,
        afi: Some(afi),
        safi: Some(safi),
        prefix: Some(f[12].into()),
        path_id: Some(path_id),
        asn,
        community: optional_u32(f[15])?,
        large_community,
        extended_community,
        next_hop: optional_ip(f[18])?,
        ..Query::default()
    };
    query.validate()?;
    Ok(Expectation {
        id: f[0].into(),
        presence,
        declaration: value.into(),
        query,
        direction,
        peer,
        checkpoint,
        lifecycle,
    })
}
fn parse_u32(value: &str) -> Result<u32> {
    u32::try_from(canonical_u64(value)?)
        .map_err(|_| bad("bgp_expectation_profile", 0, "u32 out of range"))
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct NativeScope {
    source: crate::deep::bgp_session::SourcePartition,
    session: Option<String>,
    generation: Option<u64>,
    direction: Option<u8>,
    peer: Option<String>,
    checkpoint: Option<String>,
    lifecycle: Option<u64>,
}
impl NativeScope {
    fn json(&self) -> Json {
        Json::object([
            ("source_id", self.source.source_id.clone().into()),
            ("partition_id", self.source.partition_id.clone().into()),
            (
                "source_kind",
                if self.source.kind == PartitionKind::Captured {
                    "captured"
                } else {
                    "imported"
                }
                .into(),
            ),
            (
                "session",
                self.session.clone().map_or(Json::Null, Json::from),
            ),
            ("generation", self.generation.map_or(Json::Null, Json::from)),
            ("direction", self.direction.map_or(Json::Null, Json::from)),
            ("peer", self.peer.clone().map_or(Json::Null, Json::from)),
            (
                "checkpoint_id",
                self.checkpoint.clone().map_or(Json::Null, Json::from),
            ),
            (
                "captured_lifecycle",
                self.lifecycle.map_or(Json::Null, Json::from),
            ),
        ])
    }
}
fn native_scope(store: &VerifiedStore, index: usize, limits: &Limits) -> Result<NativeScope> {
    let o = &store.observations[index];
    let s = o.source();
    let source = store.observation_partition(index, limits)?;
    Ok(NativeScope {
        source,
        session: s.session.clone(),
        generation: s.generation,
        direction: s.direction,
        peer: s.peer.clone(),
        checkpoint: o.import_context().map(|c| c.checkpoint_id.clone()),
        lifecycle: store
            .captured_observation_evidence
            .get(index)
            .map(|c| c.lifecycle),
    })
}
/// An operation-local access path over immutable verified observation ordinals.
/// It carries no continuity state: the native producer remains the effect owner.
struct ScopeGroup {
    scope: NativeScope,
    // Created once from scope during admitted construction, then immutable.
    // This matching projection never owns or reduces continuity state.
    rib_scope: Option<crate::deep::bgp_rib::RibScope>,
    ordinals: Vec<usize>,
}
struct ScopeInventory {
    groups: Vec<ScopeGroup>,
    observation_groups: Vec<usize>,
    allocation: usize,
}
impl ScopeInventory {
    fn new(
        store: &VerifiedStore,
        held_allocation: usize,
        work: &mut usize,
        limits: &Limits,
    ) -> Result<Self> {
        // Admit the worst case (one group per observation), its ordinals/map,
        // and temporary scope construction before any inventory allocation.
        let mut allocation = 0usize;
        for observation in &store.observations {
            let source = observation.source();
            let mut labels = source
                .source_id
                .len()
                .checked_add(store.namespace.len())
                .and_then(|n| n.checked_add(source.session.as_ref().map_or(0, String::len)))
                .and_then(|n| n.checked_add(source.peer.as_ref().map_or(0, String::len)))
                .ok_or_else(|| Error::limit("bgp_analysis_scope_inventory_allocation"))?;
            if let Some(context) = observation.import_context() {
                for size in [
                    context.source_id.len(),
                    context.session.len(),
                    context.source_schema.len(),
                    context.source_version.as_ref().map_or(0, String::len),
                    context.checkpoint_id.len(),
                    context.peer.as_ref().map_or(0, String::len),
                    context.local.as_ref().map_or(0, String::len),
                    context.batch.batch_id.as_ref().map_or(0, String::len),
                    context.batch.sha256.as_ref().map_or(0, String::len),
                ] {
                    labels = labels
                        .checked_add(size)
                        .ok_or_else(|| Error::limit("bgp_analysis_scope_inventory_allocation"))?;
                }
            }
            // String escaping is at most six bytes per input byte; twelve
            // covers partition serialization scratch and retained scope copies.
            // Fixed charge includes map/vector/group slots and numeric JSON keys.
            let bytes = labels
                .checked_mul(12)
                .and_then(|n| n.checked_add(2048))
                .ok_or_else(|| Error::limit("bgp_analysis_scope_inventory_allocation"))?;
            admit_allocation(bytes, &mut allocation, limits)?;
        }
        if held_allocation
            .checked_add(allocation)
            .is_none_or(|n| n > limits.retained_bytes)
        {
            return Err(Error::limit("bgp_analysis_scope_inventory_allocation"));
        }
        let comparisons = store
            .observations
            .len()
            .checked_mul(
                (usize::BITS - store.observations.len().max(1).leading_zeros()) as usize + 1,
            )
            .ok_or_else(|| Error::limit("bgp_analysis_scope_inventory_allocation"))?;
        charge_work(
            work,
            allocation
                .checked_add(comparisons)
                .ok_or_else(|| Error::limit("bgp_analysis_scope_inventory_allocation"))?,
            limits,
        )?;
        let mut grouped: BTreeMap<NativeScope, Vec<usize>> = BTreeMap::new();
        for oi in 0..store.observations.len() {
            let ordinals = grouped.entry(native_scope(store, oi, limits)?).or_default();
            ordinals
                .try_reserve(1)
                .map_err(|_| Error::limit("bgp_analysis_scope_inventory_allocation"))?;
            ordinals.push(oi);
        }
        let mut groups = Vec::new();
        groups
            .try_reserve_exact(grouped.len())
            .map_err(|_| Error::limit("bgp_analysis_scope_inventory_allocation"))?;
        let mut observation_groups = Vec::new();
        observation_groups
            .try_reserve_exact(store.observations.len())
            .map_err(|_| Error::limit("bgp_analysis_scope_inventory_allocation"))?;
        observation_groups.resize(store.observations.len(), 0);
        for (scope, ordinals) in grouped {
            let gi = groups.len();
            for &oi in &ordinals {
                observation_groups[oi] = gi;
            }
            let rib_scope =
                scope
                    .session
                    .as_ref()
                    .zip(scope.generation)
                    .map(|(session, generation)| crate::deep::bgp_rib::RibScope {
                        source: scope.source.clone(),
                        session: session.clone(),
                        generation,
                        direction: scope.direction,
                        peer: scope.peer.clone(),
                    });
            groups.push(ScopeGroup {
                scope,
                rib_scope,
                ordinals,
            });
        }
        Ok(Self {
            groups,
            observation_groups,
            allocation,
        })
    }
    fn lookup_work(&self) -> usize {
        (usize::BITS - self.groups.len().max(1).leading_zeros()) as usize * 2 + 1
    }
    fn scope(&self, oi: usize) -> &NativeScope {
        &self.groups[self.observation_groups[oi]].scope
    }
    fn session_range(
        &self,
        source: &crate::deep::bgp_session::SourcePartition,
        session: &str,
    ) -> std::ops::Range<usize> {
        let compare = |group: &ScopeGroup| {
            group
                .scope
                .source
                .cmp(source)
                .then_with(|| group.scope.session.as_deref().cmp(&Some(session)))
        };
        self.groups.partition_point(|g| compare(g).is_lt())
            ..self.groups.partition_point(|g| !compare(g).is_gt())
    }
    fn expectation_ordinals(
        &self,
        e: &Expectation,
        work: &mut usize,
        limits: &Limits,
    ) -> Result<&[usize]> {
        charge_work(work, self.lookup_work(), limits)?;
        // The exact expectation scope includes native absence, never wildcard.
        // Source/session narrowing avoids constructing another partition/projection.
        let source = e.query.source.as_deref();
        let partition = e.query.partition.as_deref();
        let compare = |group: &ScopeGroup| {
            Some(group.scope.source.source_id.as_str())
                .cmp(&source)
                .then_with(|| Some(group.scope.source.partition_id.as_str()).cmp(&partition))
                .then_with(|| group.scope.session.cmp(&e.query.session))
        };
        // Imported and captured groups have different SourcePartition kind order;
        // select that kind from the explicit lifecycle rather than an ambient default.
        let kind = if e.lifecycle.is_some() {
            PartitionKind::Captured
        } else {
            PartitionKind::Imported
        };
        let compare = |g: &ScopeGroup| g.scope.source.kind.cmp(&kind).then_with(|| compare(g));
        let start = self.groups.partition_point(|g| compare(g).is_lt());
        let end = self.groups.partition_point(|g| !compare(g).is_gt());
        charge_work(work, end - start, limits)?;
        Ok(self.groups[start..end]
            .iter()
            .find(|g| expectation_scope(e, &g.scope))
            .map_or(&[], |g| g.ordinals.as_slice()))
    }
    fn imported_effect_matches(
        &self,
        gi: usize,
        effect: &crate::deep::bgp_import::ImportedNativeContinuity,
        work: &mut usize,
        limits: &Limits,
    ) -> Result<bool> {
        charge_work(work, 1, limits)?;
        Ok(self.groups[gi]
            .rib_scope
            .as_ref()
            .is_some_and(|scope| effect.affects_scope(scope)))
    }
}
fn expectation_scope(e: &Expectation, s: &NativeScope) -> bool {
    e.query.source.as_deref() == Some(s.source.source_id.as_str())
        && e.query.partition.as_deref() == Some(s.source.partition_id.as_str())
        && e.query.session == s.session
        && e.query.generation == s.generation
        && e.direction == s.direction
        && e.peer == s.peer
        && e.checkpoint == s.checkpoint
        && e.lifecycle == s.lifecycle
}
fn expectation_route(e: &Expectation, r: &RouteObservation) -> bool {
    e.query.afi == Some(r.prefix().afi)
        && e.query.safi == Some(r.prefix().safi)
        && e.query.prefix.as_deref()
            == Some(format!("{}/{}", r.prefix().address, r.prefix().length).as_str())
        && e.query.path_id
            == Some(match r.path_id() {
                RoutePathId::Absent => PathId::Absent,
                RoutePathId::Present(n) => PathId::Present(n),
            })
}
fn observation_reference(store: &VerifiedStore, index: usize) -> Json {
    let o = &store.observations[index];
    let c = store.captured_observation_evidence.get(index);
    Json::object([
        ("observation_index", index.into()),
        ("source_occurrence_id", store.occurrence_id(o).into()),
        ("record_id", o.source().record_id.clone().into()),
        (
            "normalized_observation_sha256",
            sha256::hex(&o.sha256()).into(),
        ),
        (
            "source_record_index",
            c.map_or(Json::Null, |c| c.source_record_index.into()),
        ),
        (
            "journal_record_sha256",
            c.map_or(Json::Null, |c| sha256::hex(&c.journal_record_sha256).into()),
        ),
        (
            "source_start",
            c.map_or(Json::Null, |c| c.source_start.into()),
        ),
        ("source_end", c.map_or(Json::Null, |c| c.source_end.into())),
        ("clock", clock_json(&observation_clock(o, &store.namespace))),
        (
            "observed_at_ns",
            o.source()
                .observed_at_ns
                .map_or(Json::Null, |n| n.to_string().into()),
        ),
        (
            "import_context",
            o.import_context().map_or(Json::Null, |c| c.json()),
        ),
    ])
}
fn event_kind(o: &Observation) -> &'static str {
    match o.kind() {
        ObservationKind::Routes if o.routes().is_empty() => "route_control_or_end_of_rib",
        ObservationKind::Routes => "routes",
        ObservationKind::Open => "open",
        ObservationKind::Notification => "notification",
        ObservationKind::Keepalive => "keepalive",
        ObservationKind::RouteRefresh => "route_refresh",
        ObservationKind::Reset => "reset",
    }
}
struct ExpectationEvaluation {
    status: &'static str,
    reason: &'static str,
    matched: Vec<(usize, usize)>,
    uncertain: Vec<(usize, Option<usize>)>,
    scoped_observations: usize,
    mismatches: usize,
    boundary_witnesses: Vec<usize>,
    imported_boundary_witnesses: Vec<usize>,
}
impl VerifiedStore {
    pub fn expectations(&self, profile: &ExpectationProfile, limits: &Limits) -> Result<String> {
        limits.validate()?;
        preflight_envelope(self, limits)?;
        preflight_store(self, limits)?;
        if profile.expectations.is_empty() || profile.expectations.len() > limits.elements.min(256)
        {
            return Err(Error::limit("bgp_expectation_rows"));
        }
        // Revalidate the immutable parsed profile at the consumer boundary.
        identity(&profile.provenance)?;
        let route_members = self
            .observations
            .iter()
            .try_fold(0usize, |n, o| n.checked_add(o.routes().len()))
            .ok_or_else(|| Error::limit("bgp_expectation_work"))?;
        let cut_members = self
            .imported_source_events
            .iter()
            .try_fold(0usize, |n, e| {
                n.checked_add(e.continuity_cuts.len())
                    .and_then(|n| n.checked_add(e.native_continuity.len()))
            })
            .ok_or_else(|| Error::limit("bgp_expectation_work"))?;
        let member_bound = profile
            .expectations
            .len()
            .checked_mul(
                self.observations
                    .len()
                    .checked_add(self.captured_source_events.len())
                    .and_then(|n| n.checked_add(self.imported_source_events.len()))
                    .and_then(|n| n.checked_add(route_members))
                    .and_then(|n| n.checked_add(cut_members))
                    .ok_or_else(|| Error::limit("bgp_expectation_work"))?,
            )
            .ok_or_else(|| Error::limit("bgp_expectation_work"))?;
        if member_bound > limits.work
            || member_bound
                .checked_mul(64)
                .is_none_or(|n| n > limits.retained_bytes)
        {
            return Err(Error::limit("bgp_expectation_work"));
        }
        let mut work = 0usize;
        let inventory = ScopeInventory::new(self, member_bound * 64, &mut work, limits)?;
        let mut evaluations = Vec::new();
        for e in &profile.expectations {
            e.query.validate()?;
            identity(&e.id)?;
            let scoped_ordinals = inventory.expectation_ordinals(e, &mut work, limits)?;
            let mut evaluation = ExpectationEvaluation {
                status: "unresolved",
                reason: "unknown_source_coverage",
                matched: Vec::new(),
                uncertain: Vec::new(),
                scoped_observations: 0,
                mismatches: 0,
                boundary_witnesses: Vec::new(),
                imported_boundary_witnesses: Vec::new(),
            };
            for &oi in scoped_ordinals {
                let o = &self.observations[oi];
                work = work
                    .checked_add(1 + o.routes().len())
                    .ok_or_else(|| Error::limit("bgp_expectation_work"))?;
                if work > limits.work {
                    return Err(Error::limit("bgp_expectation_work"));
                }
                evaluation.scoped_observations += 1;
                // Captured MESSAGE effects come only from the native carrier;
                // preserve the established imported control-evidence contract.
                if o.import_context().is_some()
                    && matches!(
                        o.kind(),
                        ObservationKind::Reset | ObservationKind::Notification
                    )
                {
                    push_uncertain(&mut evaluation, (oi, None), limits)?;
                }
                for (ri, r) in o.routes().iter().enumerate() {
                    if !expectation_route(e, r) || r.action() != bgp::RouteAction::Announce {
                        continue;
                    }
                    if !e
                        .query
                        .route_attribute_uncertainties(r, o.normalized(), ri)
                        .is_empty()
                    {
                        push_uncertain(&mut evaluation, (oi, Some(ri)), limits)?;
                    }
                    match e.query.route_attributes_match(r, o.normalized(), ri) {
                        AttributeMatch::Matched => {
                            if evaluation.matched.len() >= limits.elements {
                                return Err(Error::limit("bgp_expectation_witnesses"));
                            }
                            evaluation.matched.push((oi, ri));
                        }
                        AttributeMatch::NotMatched => evaluation.mismatches += 1,
                        AttributeMatch::Uncertain(_) => {
                            if evaluation.uncertain.last() != Some(&(oi, Some(ri))) {
                                push_uncertain(&mut evaluation, (oi, Some(ri)), limits)?;
                            }
                        }
                    }
                }
            }
            // Journal gaps, resets, end/clear and rejected containers remain scope-
            // bound uncertainty; they can never be converted to missing routes.
            for (ei, event) in self.captured_source_events.iter().enumerate() {
                work = work
                    .checked_add(1)
                    .ok_or_else(|| Error::limit("bgp_expectation_work"))?;
                if work > limits.work {
                    return Err(Error::limit("bgp_expectation_work"));
                }
                let mut relevant = false;
                if event.continuity.is_some() {
                    // The producer owns scope/effect semantics, including inert
                    // immutable replay and whole-generation native quarantine.
                    if let Some(&oi) = scoped_ordinals.first() {
                        charge_work(&mut work, 1, limits)?;
                        if captured_continuity_matches(self, ei, oi, &mut work, limits)? {
                            relevant = true;
                        }
                    }
                } else {
                    relevant = event.scopes.iter().any(|s| {
                        e.query.session.as_deref() == Some(s.session.to_string().as_str())
                            && e.lifecycle == Some(s.lifecycle)
                            && s.generation.is_none_or(|g| e.query.generation == Some(g))
                            && e.query.partition.as_deref()
                                == Some(
                                    format!(
                                        "{}:captured-lifecycle:{}",
                                        self.namespace, s.lifecycle
                                    )
                                    .as_str(),
                                )
                    });
                }
                if relevant {
                    evaluation.reason = "native_boundary_or_rejected_source";
                    if evaluation.boundary_witnesses.len() >= limits.elements {
                        return Err(Error::limit("bgp_expectation_witnesses"));
                    }
                    evaluation.boundary_witnesses.push(ei);
                }
            }
            for (ei, event) in self.imported_source_events.iter().enumerate() {
                work = work
                    .checked_add(1)
                    .ok_or_else(|| Error::limit("bgp_expectation_work"))?;
                if work > limits.work {
                    return Err(Error::limit("bgp_expectation_work"));
                }
                work = work
                    .checked_add(event.continuity_cuts.len())
                    .ok_or_else(|| Error::limit("bgp_expectation_work"))?;
                if work > limits.work {
                    return Err(Error::limit("bgp_expectation_work"));
                }
                let mut matches = false;
                if e.query.source.as_deref() == Some(event.source_id.as_str())
                    && e.checkpoint.as_deref() == Some(event.checkpoint_id.as_str())
                    && e.lifecycle.is_none()
                {
                    for effect in &event.native_continuity {
                        charge_work(&mut work, 1, limits)?;
                        if let Some(&oi) = scoped_ordinals.first() {
                            let gi = inventory.observation_groups[oi];
                            matches |=
                                inventory.imported_effect_matches(gi, effect, &mut work, limits)?;
                        }
                        let scope = imported_effect_scope(effect, &event.checkpoint_id);
                        if expectation_scope(e, &scope) {
                            matches = true;
                        }
                    }
                    // Opaque source evidence can contain unparsed routes even
                    // without a native mutation. Preserve source/checkpoint-
                    // fenced coverage uncertainty separately from continuity.
                    if event.kind == crate::deep::bgp_import::ImportedSourceEventKind::Opaque {
                        if let Some(c) = &event.context {
                            matches |= expectation_scope(e, &import_context_scope(c, limits)?);
                        } else if event.continuity_cuts.is_empty() {
                            matches = true;
                        }
                    }
                }
                if matches {
                    if evaluation.imported_boundary_witnesses.len() >= limits.elements {
                        return Err(Error::limit("bgp_expectation_witnesses"));
                    }
                    evaluation.imported_boundary_witnesses.push(ei);
                }
            }
            if !evaluation.matched.is_empty() {
                evaluation.status = if e.presence == ExpectedPresence::Present {
                    "supported"
                } else {
                    "contradicted"
                };
                evaluation.reason = "exact_matching_announcement_observed";
            } else if evaluation.scoped_observations == 0 {
                evaluation.reason = "no_observed_exact_scope";
            } else if !evaluation.uncertain.is_empty()
                || !evaluation.boundary_witnesses.is_empty()
                || !evaluation.imported_boundary_witnesses.is_empty()
            {
                evaluation.reason = "incomplete_or_boundary_evidence";
            } else if profile.coverage == CoverageDeclaration::CallerDeclaredComplete {
                evaluation.status = if e.presence == ExpectedPresence::Absent {
                    "supported"
                } else {
                    "contradicted"
                };
                evaluation.reason = "conditional_on_caller_declared_complete_coverage";
            }
            evaluations.push(evaluation);
        }
        let mut allocation = profile
            .expectations
            .len()
            .checked_mul(8192)
            .and_then(|n| n.checked_add(inventory.allocation))
            .ok_or_else(|| Error::limit("bgp_analysis_allocation"))?;
        for evaluation in &evaluations {
            for &(oi, _) in &evaluation.matched {
                admit_witness_allocation(self, oi, &mut allocation, limits)?;
            }
            for &(oi, _) in &evaluation.uncertain {
                admit_witness_allocation(self, oi, &mut allocation, limits)?;
            }
            for &ei in &evaluation.boundary_witnesses {
                admit_allocation(
                    self.captured_source_events[ei]
                        .retained_charge()
                        .saturating_mul(12),
                    &mut allocation,
                    limits,
                )?;
            }
            for &ei in &evaluation.imported_boundary_witnesses {
                admit_allocation(
                    imported_source_event_charge(&self.imported_source_events[ei], limits)?
                        .saturating_mul(12),
                    &mut allocation,
                    limits,
                )?;
            }
        }
        let base = expectation_document(self, profile, &evaluations, false);
        let mut borrowed = Vec::new();
        for evaluation in &evaluations {
            for &(oi, ri) in &evaluation.matched {
                borrowed.push(self.observations[oi].routes()[ri].semantic_identity());
            }
            for &(oi, ri) in &evaluation.uncertain {
                if oi != usize::MAX {
                    borrowed.push(ri.map_or(self.observations[oi].normalized(), |ri| {
                        self.observations[oi].routes()[ri].semantic_identity()
                    }));
                }
            }
        }
        admit_borrowed_document(&base, &borrowed, limits)?;
        bounded_output(
            expectation_document(self, profile, &evaluations, true),
            limits,
        )
    }
}
fn push_uncertain(
    e: &mut ExpectationEvaluation,
    witness: (usize, Option<usize>),
    limits: &Limits,
) -> Result<()> {
    if e.uncertain.len() >= limits.elements {
        return Err(Error::limit("bgp_expectation_witnesses"));
    }
    e.uncertain.push(witness);
    Ok(())
}
fn expectation_document(
    store: &VerifiedStore,
    profile: &ExpectationProfile,
    results: &[ExpectationEvaluation],
    full: bool,
) -> Json {
    Json::object([
        ("schema", EXPECTATION_RESULT_SCHEMA.into()),
        ("store", store.reference()),
        ("profile_sha256", profile.profile_sha256.clone().into()),
        ("profile_schema", profile.schema.into()),
        ("caller_provenance", profile.provenance.clone().into()),
        ("time_basis", "source_occurrence_order".into()),
        ("coverage_declaration", profile.coverage.name().into()),
        ("verified_source_coverage", "unknown".into()),
        (
            "expectation_semantics",
            "existence_of_matching_announced_occurrence_in_exact_scope".into(),
        ),
        (
            "results",
            Json::array(profile.expectations.iter().zip(results).map(|(e, r)| {
                Json::object([
                    ("id", e.id.clone().into()),
                    ("caller_expectation_row", e.declaration.clone().into()),
                    (
                        "expected",
                        if e.presence == ExpectedPresence::Present {
                            "present"
                        } else {
                            "absent"
                        }
                        .into(),
                    ),
                    ("status", r.status.into()),
                    ("reason", r.reason.into()),
                    ("scoped_observations", r.scoped_observations.into()),
                    ("complete_selector_mismatches", r.mismatches.into()),
                    (
                        "scope",
                        Json::object([
                            (
                                "source_id",
                                e.query.source.clone().map_or(Json::Null, Json::from),
                            ),
                            (
                                "partition_id",
                                e.query.partition.clone().map_or(Json::Null, Json::from),
                            ),
                            (
                                "session",
                                e.query.session.clone().map_or(Json::Null, Json::from),
                            ),
                            (
                                "generation",
                                e.query.generation.map_or(Json::Null, Json::from),
                            ),
                            ("direction", e.direction.map_or(Json::Null, Json::from)),
                            ("peer", e.peer.clone().map_or(Json::Null, Json::from)),
                            (
                                "checkpoint_id",
                                e.checkpoint.clone().map_or(Json::Null, Json::from),
                            ),
                            (
                                "captured_lifecycle",
                                e.lifecycle.map_or(Json::Null, Json::from),
                            ),
                            ("afi", e.query.afi.map_or(Json::Null, Json::from)),
                            ("safi", e.query.safi.map_or(Json::Null, Json::from)),
                            (
                                "prefix",
                                e.query.prefix.clone().map_or(Json::Null, Json::from),
                            ),
                            (
                                "path_id",
                                match e.query.path_id {
                                    Some(PathId::Absent) => Json::Null,
                                    Some(PathId::Present(n)) => n.into(),
                                    _ => "unknown".into(),
                                },
                            ),
                        ]),
                    ),
                    (
                        "witnesses",
                        Json::array(
                            r.matched
                                .iter()
                                .map(|&(oi, ri)| expectation_witness(store, oi, Some(ri), full)),
                        ),
                    ),
                    (
                        "uncertain_witnesses",
                        Json::array(
                            r.uncertain
                                .iter()
                                .map(|&(oi, ri)| expectation_witness(store, oi, ri, full)),
                        ),
                    ),
                    (
                        "boundary_witnesses",
                        Json::array(
                            r.boundary_witnesses
                                .iter()
                                .map(|&ei| store.captured_source_events[ei].json()),
                        ),
                    ),
                    (
                        "imported_boundary_witnesses",
                        Json::array(
                            r.imported_boundary_witnesses
                                .iter()
                                .map(|&ei| store.imported_source_events[ei].reference.clone()),
                        ),
                    ),
                ])
            })),
        ),
        ("source_authenticated", false.into()),
        ("endpoint_state_claimed", false.into()),
        ("route_installation_claimed", false.into()),
    ])
}
fn expectation_witness(store: &VerifiedStore, oi: usize, ri: Option<usize>, full: bool) -> Json {
    Json::object([
        ("reference", observation_reference(store, oi)),
        ("route_index", ri.map_or(Json::Null, Json::from)),
        (
            "evidence",
            if full {
                ri.map_or_else(
                    || store.observations[oi].normalized().clone(),
                    |ri| {
                        store.observations[oi].routes()[ri]
                            .semantic_identity()
                            .clone()
                    },
                )
            } else {
                Json::Null
            },
        ),
    ])
}
fn admit_allocation(bytes: usize, total: &mut usize, limits: &Limits) -> Result<()> {
    *total = total
        .checked_add(bytes)
        .ok_or_else(|| Error::limit("bgp_analysis_allocation"))?;
    if *total > limits.retained_bytes || *total > limits.work {
        return Err(Error::limit("bgp_analysis_allocation"));
    }
    Ok(())
}
fn admit_witness_allocation(
    store: &VerifiedStore,
    oi: usize,
    total: &mut usize,
    limits: &Limits,
) -> Result<()> {
    let bytes = store.observations[oi]
        .normalized()
        .encoded_len_bounded(limits.retained_bytes)?
        .checked_add(8192)
        .and_then(|n| n.checked_mul(12))
        .ok_or_else(|| Error::limit("bgp_analysis_allocation"))?;
    admit_allocation(bytes, total, limits)
}
fn admit_borrowed_document(base: &Json, borrowed: &[&Json], limits: &Limits) -> Result<()> {
    let cap = limits
        .output_bytes
        .min(limits.retained_bytes)
        .min(limits.work);
    let mut size = base.encoded_len_bounded(cap)?;
    let mut nodes = 0;
    let mut spans = reference_spans(base);
    if spans > limits.spans {
        return Err(Error::limit("bgp_analysis_spans"));
    }
    inspect_borrowed(base, 0, &mut nodes, limits)?;
    for value in borrowed {
        inspect_borrowed(value, 4, &mut nodes, limits)?;
        spans = spans
            .checked_add(reference_spans(value))
            .ok_or_else(|| Error::limit("bgp_analysis_spans"))?;
        if spans > limits.spans {
            return Err(Error::limit("bgp_analysis_spans"));
        }
        size = size
            .checked_sub(4)
            .and_then(|n| n.checked_add(value.encoded_len_bounded(cap).ok()?))
            .ok_or_else(|| Error::limit("bgp_analysis_output"))?;
        if size > cap {
            return Err(Error::limit("bgp_analysis_output"));
        }
    }
    guard_projection(size, limits)
}

#[derive(Clone, Copy)]
enum SourceItem {
    Observation(usize),
    CapturedBoundary(usize),
    ImportedBoundary(usize),
}
#[derive(Clone, Copy)]
struct OrderedItem {
    record: u64,
    suborder: usize,
    item: SourceItem,
}
#[derive(Clone)]
struct Change {
    item: SourceItem,
    route_index: Option<usize>,
    before: Option<(usize, usize)>,
    difference: &'static str,
    selector: &'static str,
    eor: Option<Vec<Family>>,
}
struct SelectorAvailability {
    observation_index: usize,
    route_index: usize,
    causes: Vec<&'static str>,
    match_disposition: &'static str,
}
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct ChangeKey {
    prefix: PrefixIdentity,
    path_id: RoutePathId,
}
fn query_scope(query: &Query, scope: &NativeScope) -> bool {
    query
        .source
        .as_ref()
        .is_none_or(|v| v == &scope.source.source_id)
        && query
            .partition
            .as_ref()
            .is_none_or(|v| v == &scope.source.partition_id)
        && query
            .session
            .as_ref()
            .is_none_or(|v| Some(v) == scope.session.as_ref())
        && query.generation.is_none_or(|v| Some(v) == scope.generation)
        && query.direction.is_none_or(|v| Some(v) == scope.direction)
        && query
            .peer
            .as_ref()
            .is_none_or(|v| Some(v) == scope.peer.as_ref())
        && query
            .checkpoint
            .as_ref()
            .is_none_or(|v| Some(v) == scope.checkpoint.as_ref())
        && query.lifecycle.is_none_or(|v| Some(v) == scope.lifecycle)
}
fn selector_metadata_uncertainties(
    query: &Query,
    prefix: &PrefixIdentity,
    source: &str,
    clock: &ObservationClock,
    time: Option<i64>,
) -> Vec<&'static str> {
    let mut causes = Vec::new();
    if query
        .prefix_selector
        .as_ref()
        .is_some_and(|p| p.matches(prefix).is_none())
    {
        causes.push("unsupported_prefix");
    }
    if query.time_window.as_ref().is_some_and(|window| {
        super::query::time_match(window, source, clock, time) == super::query::Verdict::Unknown
    }) {
        causes.push("missing_reported_clock_or_time");
    }
    causes
}
fn query_route(
    query: &Query,
    route: &RouteObservation,
    o: &Observation,
    ri: usize,
    clock: &ObservationClock,
) -> &'static str {
    if query.afi.is_some_and(|v| v != route.prefix().afi)
        || query.safi.is_some_and(|v| v != route.prefix().safi)
        || query
            .prefix
            .as_ref()
            .is_some_and(|v| v != &format!("{}/{}", route.prefix().address, route.prefix().length))
        || query.path_id.is_some_and(|v| {
            v != match route.path_id() {
                RoutePathId::Absent => PathId::Absent,
                RoutePathId::Present(n) => PathId::Present(n),
            }
        })
    {
        return "not_matched";
    }
    let mut unknown = false;
    if let Some(prefix) = &query.prefix_selector {
        match prefix.matches(route.prefix()) {
            Some(false) => return "not_matched",
            None => unknown = true,
            _ => {}
        }
    }
    if let Some(window) = &query.time_window {
        match super::query::time_match(
            window,
            &o.source().source_id,
            clock,
            o.source().observed_at_ns,
        ) {
            super::query::Verdict::No => return "not_matched",
            super::query::Verdict::Unknown => unknown = true,
            _ => {}
        }
    }
    match query.route_attributes_match(route, o.normalized(), ri) {
        AttributeMatch::NotMatched => "not_matched",
        AttributeMatch::Uncertain(_) => "unresolved",
        AttributeMatch::Matched if unknown => "unresolved",
        AttributeMatch::Matched => "matched",
    }
}
impl VerifiedStore {
    /// One sealed store's source record order, with independent native partitions.
    /// Before/after is an observed attribute identity comparison, never a withdrawal
    /// inferred from absence, an endpoint RIB, or concatenated checkpoint state.
    pub fn changes(&self, query: &Query, limits: &Limits) -> Result<String> {
        limits.validate()?;
        query.validate()?;
        preflight_envelope(self, limits)?;
        preflight_store(self, limits)?;
        if query.status.is_some()
            || query.version_index.is_some()
            || query.occurrence_id.is_some()
            || matches!(
                query.attribute_scope,
                Some(
                    super::query::AttributeScope::CurrentEffective
                        | super::query::AttributeScope::ObservationEvent
                )
            )
        {
            return Err(bad(
                "bgp_changes_query",
                0,
                "source occurrences do not accept terminal-row or version selectors",
            ));
        }
        let count = self
            .observations
            .len()
            .checked_add(self.captured_source_events.len())
            .and_then(|n| n.checked_add(self.imported_source_events.len()))
            .ok_or_else(|| Error::limit("bgp_changes_items"))?;
        let route_count = self
            .observations
            .iter()
            .try_fold(0usize, |n, o| n.checked_add(o.routes().len()))
            .ok_or_else(|| Error::limit("bgp_changes_items"))?;
        if count
            .checked_add(route_count)
            .is_none_or(|n| n > limits.elements)
        {
            return Err(Error::limit("bgp_changes_items"));
        }
        let estimated = count
            .checked_add(route_count)
            .and_then(|n| n.checked_mul(8192))
            .ok_or_else(|| Error::limit("bgp_changes_retained"))?;
        if estimated > limits.retained_bytes {
            return Err(Error::limit("bgp_changes_retained"));
        }
        let mut inventory_work = 0usize;
        let inventory = ScopeInventory::new(self, estimated, &mut inventory_work, limits)?;
        let mut items = Vec::new();
        items
            .try_reserve_exact(count)
            .map_err(|_| Error::limit("bgp_changes_allocation"))?;
        let mut imported_order = vec![None; self.observations.len()];
        for event in &self.imported_source_events {
            if let Some(oi) = event.observation_index {
                let slot = imported_order.get_mut(oi).ok_or_else(|| {
                    bad(
                        "bgp_changes_source_order",
                        0,
                        "typed observation index out of range",
                    )
                })?;
                if slot.is_some_and(|record| record != event.source_record_index as u64) {
                    return Err(bad(
                        "bgp_changes_source_order",
                        0,
                        "conflicting source occurrence binding",
                    ));
                }
                *slot = Some(event.source_record_index as u64);
            }
        }
        // This vector is allocated at exactly observations.len() and never resized.
        // Enumeration preserves every verified observation's original index.
        for (oi, imported_record) in imported_order.iter().enumerate() {
            let record = if let Some(c) = self.captured_observation_evidence.get(oi) {
                c.source_record_index
            } else {
                imported_record.ok_or_else(|| {
                    bad(
                        "bgp_changes_source_order",
                        0,
                        "typed source occurrence missing",
                    )
                })?
            };
            items.push(OrderedItem {
                record,
                suborder: oi + 1,
                item: SourceItem::Observation(oi),
            });
        }
        for (ei, e) in self.captured_source_events.iter().enumerate() {
            items.push(OrderedItem {
                record: e.source_record_index,
                suborder: 0,
                item: SourceItem::CapturedBoundary(ei),
            });
        }
        for (ei, e) in self.imported_source_events.iter().enumerate() {
            if e.observation_index.is_none()
                || !e.continuity_cuts.is_empty()
                || imported_event_breaks_continuity(e)
            {
                items.push(OrderedItem {
                    record: e.source_record_index as u64,
                    suborder: 0,
                    item: SourceItem::ImportedBoundary(ei),
                });
            }
        }
        // Source ordinal sort only. No reported clock or cross-store input participates.
        items.sort_by_key(|e| (e.record, e.suborder));
        let mut previous: BTreeMap<usize, BTreeMap<ChangeKey, (usize, usize)>> = BTreeMap::new();
        let mut changes = Vec::new();
        let mut availability = Vec::new();
        let mut work = count
            .checked_mul((usize::BITS - count.max(1).leading_zeros()) as usize + 2)
            .and_then(|n| n.checked_add(inventory_work))
            .ok_or_else(|| Error::limit("bgp_changes_work"))?;
        if work > limits.work {
            return Err(Error::limit("bgp_changes_work"));
        }
        for item in items {
            work = work
                .checked_add(1)
                .ok_or_else(|| Error::limit("bgp_changes_work"))?;
            if work > limits.work {
                return Err(Error::limit("bgp_changes_work"));
            }
            match item.item {
                SourceItem::Observation(oi) => {
                    let o = &self.observations[oi];
                    let scope = inventory.scope(oi);
                    let gi = inventory.observation_groups[oi];
                    if o.routes().is_empty() && query_scope(query, scope) {
                        changes.push(Change {
                            item: item.item,
                            route_index: None,
                            before: None,
                            difference: "control_event_no_route_action",
                            selector: "scope_matched",
                            eor: o.end_of_rib_families()?,
                        });
                    }
                    for (ri, r) in o.routes().iter().enumerate() {
                        work = work
                            .checked_add(1)
                            .ok_or_else(|| Error::limit("bgp_changes_work"))?;
                        if work > limits.work {
                            return Err(Error::limit("bgp_changes_work"));
                        }
                        let key = ChangeKey {
                            prefix: r.prefix().clone(),
                            path_id: r.path_id(),
                        };
                        let before = previous
                            .get(&gi)
                            .and_then(|routes| routes.get(&key))
                            .copied();
                        let difference = match (r.action(), before) {
                            (bgp::RouteAction::Withdraw, _) => "explicit_withdrawal_observed",
                            (_, None) => "first_announcement_in_observed_segment",
                            (_, Some((bo, br))) => {
                                let b = &self.observations[bo].routes()[br];
                                if !super::query::complete(r) || !super::query::complete(b) {
                                    "attribute_difference_unresolved"
                                } else if b.attribute_identity() == r.attribute_identity() {
                                    "unchanged_repeated_announcement"
                                } else {
                                    "complete_attribute_identity_changed"
                                }
                            }
                        };
                        let selector =
                            query_route(query, r, o, ri, &observation_clock(o, &self.namespace));
                        if query_scope(query, scope) {
                            let mut causes =
                                query.route_attribute_uncertainties(r, o.normalized(), ri);
                            causes.extend(selector_metadata_uncertainties(
                                query,
                                r.prefix(),
                                &o.source().source_id,
                                &observation_clock(o, &self.namespace),
                                o.source().observed_at_ns,
                            ));
                            if !causes.is_empty() {
                                availability.push(SelectorAvailability {
                                    observation_index: oi,
                                    route_index: ri,
                                    causes,
                                    match_disposition: selector,
                                });
                            }
                        }
                        if query_scope(query, scope) && selector != "not_matched" {
                            changes.push(Change {
                                item: item.item,
                                route_index: Some(ri),
                                before,
                                difference,
                                selector,
                                eor: None,
                            });
                        }
                        if r.action() == bgp::RouteAction::Announce {
                            previous.entry(gi).or_default().insert(key, (oi, ri));
                        } else if let Some(routes) = previous.get_mut(&gi) {
                            routes.remove(&key);
                        }
                    }
                }
                SourceItem::CapturedBoundary(ei) => {
                    let e = &self.captured_source_events[ei];
                    if e.continuity.is_some() {
                        // Reduce the complete source order before query filtering.
                        // Fallible canonical matching admits its aggregate copy work.
                        let mut failure = None;
                        previous.retain(|gi, routes| {
                            if failure.is_some() {
                                return true;
                            }
                            let oi = inventory.groups[*gi].ordinals[0];
                            match captured_continuity_matches(self, ei, oi, &mut work, limits) {
                                Ok(true) => match charge_work(&mut work, routes.len(), limits) {
                                    Ok(()) => false,
                                    Err(error) => {
                                        failure = Some(error);
                                        true
                                    }
                                },
                                Ok(false) => true,
                                Err(error) => {
                                    failure = Some(error);
                                    true
                                }
                            }
                        });
                        if let Some(error) = failure {
                            return Err(error);
                        }
                    } else {
                        charge_work(
                            &mut work,
                            previous
                                .len()
                                .checked_mul(e.scopes.len())
                                .ok_or_else(|| Error::limit("bgp_changes_work"))?,
                            limits,
                        )?;
                        charge_work(
                            &mut work,
                            previous.values().map(BTreeMap::len).sum(),
                            limits,
                        )?;
                        previous.retain(|gi, _| {
                            let scope = &inventory.groups[*gi].scope;
                            !e.scopes.iter().any(|s| {
                                scope.lifecycle == Some(s.lifecycle)
                                    && scope.session.as_deref()
                                        == Some(s.session.to_string().as_str())
                            })
                        });
                    }
                    charge_work(
                        &mut work,
                        inventory
                            .groups
                            .len()
                            .checked_mul(e.scopes.len().saturating_add(1))
                            .ok_or_else(|| Error::limit("bgp_changes_work"))?,
                        limits,
                    )?;
                    if capture_event_matches(self, &inventory, query, ei, &mut work, limits)? {
                        changes.push(Change {
                            item: item.item,
                            route_index: None,
                            before: None,
                            difference: if e
                                .continuity
                                .as_ref()
                                .is_some_and(|c| !c.decision.newly_applied)
                            {
                                "inert_native_continuity_replay_no_route_action"
                            } else {
                                "continuity_boundary_no_route_action"
                            },
                            selector: "scope_matched",
                            eor: None,
                        });
                    }
                }
                SourceItem::ImportedBoundary(ei) => {
                    let e = &self.imported_source_events[ei];
                    charge_work(
                        &mut work,
                        e.native_continuity
                            .len()
                            .checked_mul(2)
                            .ok_or_else(|| Error::limit("bgp_changes_work"))?,
                        limits,
                    )?;
                    for effect in &e.native_continuity {
                        charge_work(&mut work, inventory.lookup_work(), limits)?;
                        for gi in
                            inventory.session_range(&effect.scope.source, &effect.scope.session)
                        {
                            if inventory.imported_effect_matches(gi, effect, &mut work, limits)? {
                                // Removing a group still visits/drops its retained route keys.
                                let routes = previous.get(&gi).map_or(0, BTreeMap::len);
                                charge_work(&mut work, routes + inventory.lookup_work(), limits)?;
                                previous.remove(&gi);
                            }
                        }
                    }
                    if import_event_matches(&inventory, query, e, &mut work, limits)? {
                        changes.push(Change {
                            item: item.item,
                            route_index: None,
                            before: None,
                            difference: "source_metadata_or_boundary_no_route_action",
                            selector: "scope_matched",
                            eor: None,
                        });
                    }
                }
            }
        }
        let mut allocation = inventory.allocation;
        for c in &changes {
            match c.item {
                SourceItem::Observation(oi) => {
                    admit_witness_allocation(self, oi, &mut allocation, limits)?;
                    if let Some((bo, _)) = c.before {
                        admit_witness_allocation(self, bo, &mut allocation, limits)?;
                    }
                }
                SourceItem::CapturedBoundary(ei) => admit_allocation(
                    self.captured_source_events[ei]
                        .retained_charge()
                        .saturating_mul(12),
                    &mut allocation,
                    limits,
                )?,
                SourceItem::ImportedBoundary(ei) => admit_allocation(
                    imported_source_event_charge(&self.imported_source_events[ei], limits)?
                        .saturating_mul(12),
                    &mut allocation,
                    limits,
                )?,
            }
        }
        for a in &availability {
            admit_witness_allocation(self, a.observation_index, &mut allocation, limits)?;
        }
        let base = changes_document(self, &inventory, &changes, &availability, false)?;
        let mut borrowed = Vec::new();
        for c in &changes {
            if let SourceItem::Observation(oi) = c.item {
                borrowed.push(self.observations[oi].normalized());
                if let Some((bo, br)) = c.before {
                    borrowed.push(self.observations[bo].routes()[br].attribute_identity());
                }
                if let Some(ri) = c.route_index {
                    borrowed.push(self.observations[oi].routes()[ri].attribute_identity());
                }
            }
        }
        admit_borrowed_document(&base, &borrowed, limits)?;
        bounded_output(
            changes_document(self, &inventory, &changes, &availability, true)?,
            limits,
        )
    }
}
/// Admission and scope mapping are owned by the verified consumer adapter.
fn captured_continuity_matches(
    store: &VerifiedStore,
    event_index: usize,
    observation_index: usize,
    work: &mut usize,
    limits: &Limits,
) -> Result<bool> {
    charge_work(
        work,
        store.captured_continuity_match_charge(observation_index)?,
        limits,
    )?;
    store.captured_continuity_matches(event_index, observation_index, limits)
}
fn capture_event_matches(
    store: &VerifiedStore,
    inventory: &ScopeInventory,
    q: &Query,
    event_index: usize,
    work: &mut usize,
    limits: &Limits,
) -> Result<bool> {
    let e = &store.captured_source_events[event_index];
    if q.checkpoint.is_some() {
        return Ok(false);
    }
    if let Some(bound) = &e.continuity {
        // Preserve even inert source occurrences in their exact reporting scope.
        let witness_scope = inventory.scope(bound.observation_index);
        if query_scope(q, witness_scope) {
            return Ok(true);
        }
        for group in &inventory.groups {
            let oi = group.ordinals[0];
            let scope = &group.scope;
            if query_scope(q, scope)
                && captured_continuity_matches(store, event_index, oi, work, limits)?
            {
                return Ok(true);
            }
        }
        return Ok(false);
    }
    for group in &inventory.groups {
        let scope = &group.scope;
        if e.scopes.iter().any(|s| {
            scope.lifecycle == Some(s.lifecycle)
                && scope.session.as_deref() == Some(s.session.to_string().as_str())
        }) && query_scope(q, scope)
        {
            return Ok(true);
        }
    }
    if let Some(m) = &e.metadata {
        return Ok(q.partition.as_ref().is_none_or(|v| {
            e.scopes
                .iter()
                .any(|s| v == &format!("{}:captured-lifecycle:{}", store.namespace, s.lifecycle))
        }) && q.source.as_ref().is_none_or(|v| v == &m.source_id)
            && q.session
                .as_ref()
                .is_none_or(|v| e.scopes.iter().any(|s| v == &s.session.to_string()))
            && q.direction.is_none_or(|v| Some(v) == m.direction)
            && q.peer.as_ref().is_none_or(|v| Some(v) == m.peer.as_ref())
            && q.lifecycle
                .is_none_or(|v| e.scopes.iter().any(|s| v == s.lifecycle))
            && q.generation
                .is_none_or(|v| e.scopes.iter().any(|s| Some(v) == s.generation)));
    }
    Ok(q.partition.is_none()
        && q.source.is_none()
        && q.session.is_none()
        && q.generation.is_none()
        && q.direction.is_none()
        && q.peer.is_none()
        && q.lifecycle.is_none())
}
fn charge_work(total: &mut usize, additional: usize, limits: &Limits) -> Result<()> {
    *total = total
        .checked_add(additional)
        .ok_or_else(|| Error::limit("bgp_changes_work"))?;
    if *total > limits.work {
        return Err(Error::limit("bgp_changes_work"));
    }
    Ok(())
}
fn imported_event_breaks_continuity(e: &crate::deep::bgp_import::ImportedSourceEvent) -> bool {
    use crate::deep::bgp_import::ImportedSourceEventKind as K;
    matches!(
        e.kind,
        K::ContinuityGap | K::GenerationBoundary | K::Notification
    ) || e.kind == K::Opaque && e.context.is_some()
}
fn import_context_scope(
    c: &crate::deep::bgp_import::ImportContext,
    limits: &Limits,
) -> Result<NativeScope> {
    Ok(NativeScope {
        source: crate::deep::bgp_session::SourcePartition::from_import_context(c, limits)?,
        session: Some(c.session.clone()),
        generation: Some(c.generation),
        direction: c.direction,
        peer: c.peer.clone(),
        checkpoint: Some(c.checkpoint_id.clone()),
        lifecycle: None,
    })
}
fn imported_effect_scope(
    effect: &crate::deep::bgp_import::ImportedNativeContinuity,
    checkpoint: &str,
) -> NativeScope {
    NativeScope {
        source: effect.scope.source.clone(),
        session: Some(effect.scope.session.clone()),
        generation: Some(effect.generations().0),
        direction: effect.scope.direction,
        peer: effect.scope.peer.clone(),
        checkpoint: Some(checkpoint.into()),
        lifecycle: None,
    }
}
fn import_event_matches(
    inventory: &ScopeInventory,
    q: &Query,
    e: &crate::deep::bgp_import::ImportedSourceEvent,
    work: &mut usize,
    limits: &Limits,
) -> Result<bool> {
    if q.source
        .as_deref()
        .is_some_and(|source| source != e.source_id)
        || q.checkpoint
            .as_deref()
            .is_some_and(|checkpoint| checkpoint != e.checkpoint_id)
        || q.lifecycle.is_some()
    {
        return Ok(false);
    }
    for effect in &e.native_continuity {
        charge_work(work, inventory.lookup_work(), limits)?;
        // Canonical continuity can broaden direction within an admitted native
        // partition. Select the actual scope first; query peer text cannot
        // manufacture a different peer inside that immutable partition.
        for gi in inventory.session_range(&effect.scope.source, &effect.scope.session) {
            charge_work(work, 1, limits)?;
            if query_scope(q, &inventory.groups[gi].scope)
                && inventory.imported_effect_matches(gi, effect, work, limits)?
            {
                return Ok(true);
            }
        }
        // Gap-only native scopes can precede normalized observations. Their
        // original peer/direction identity remains exact for selector purposes.
        if query_scope(q, &imported_effect_scope(effect, &e.checkpoint_id)) {
            return Ok(true);
        }
    }
    if let Some(c) = &e.context {
        return Ok(query_scope(q, &import_context_scope(c, limits)?));
    }
    // Source/checkpoint are known even when peer/session metadata is unavailable.
    // Exact matching source selectors preserve ordinary route-free metadata.
    Ok(e.continuity_cuts.is_empty()
        && e.native_continuity.is_empty()
        && q.session.is_none()
        && q.partition.is_none()
        && q.generation.is_none()
        && q.direction.is_none()
        && q.peer.is_none())
}
fn changes_document(
    store: &VerifiedStore,
    inventory: &ScopeInventory,
    changes: &[Change],
    availability: &[SelectorAvailability],
    full: bool,
) -> Result<Json> {
    Ok(Json::object([
        ("schema", CHANGES_SCHEMA.into()),
        ("store", store.reference()),
        (
            "selector_coverage",
            Json::object([
                ("coverage_scope", "selector_fields".into()),
                ("source_coverage", "unknown".into()),
                ("uncertain_occurrences", availability.len().into()),
                (
                    "witnesses",
                    Json::array(availability.iter().map(|a| {
                        Json::object([
                            (
                                "reference",
                                observation_reference(store, a.observation_index),
                            ),
                            ("route_index", a.route_index.into()),
                            ("match_disposition", a.match_disposition.into()),
                            (
                                "unavailable_fields",
                                Json::array(a.causes.iter().map(|s| (*s).into())),
                            ),
                        ])
                    })),
                ),
            ]),
        ),
        ("order", "verified_source_record_occurrence_order".into()),
        (
            "checkpoint_semantics",
            "independent_native_partitions_no_state_concatenation".into(),
        ),
        (
            "events",
            Json::array(changes.iter().enumerate().map(|(ordinal, c)| match c.item {
                SourceItem::Observation(oi) => {
                    let o = &store.observations[oi];
                    Json::object([
                        ("ordinal", ordinal.into()),
                        (
                            "kind",
                            c.route_index
                                .map_or(
                                    if o.kind() == ObservationKind::Routes {
                                        match &c.eor {
                                            Some(f) if !f.is_empty() => "end_of_rib",
                                            Some(_) => "route_control",
                                            None => "route_control_eor_unresolved",
                                        }
                                    } else {
                                        event_kind(o)
                                    },
                                    |ri| {
                                        if o.routes()[ri].action() == bgp::RouteAction::Announce {
                                            "announce"
                                        } else {
                                            "withdraw"
                                        }
                                    },
                                )
                                .into(),
                        ),
                        ("difference", c.difference.into()),
                        ("selector_disposition", c.selector.into()),
                        (
                            "end_of_rib_families",
                            c.eor.as_ref().map_or(Json::Null, |f| {
                                Json::array(f.iter().map(|f| {
                                    Json::object([("afi", f.afi.into()), ("safi", f.safi.into())])
                                }))
                            }),
                        ),
                        ("native_scope", inventory.scope(oi).json()),
                        ("reference", observation_reference(store, oi)),
                        ("route_index", c.route_index.map_or(Json::Null, Json::from)),
                        (
                            "normalized_observation",
                            if full {
                                o.normalized().clone()
                            } else {
                                Json::Null
                            },
                        ),
                        (
                            "before_reference",
                            c.before.map_or(Json::Null, |(bo, br)| {
                                Json::object([
                                    ("observation", observation_reference(store, bo)),
                                    ("route_index", br.into()),
                                ])
                            }),
                        ),
                        (
                            "before_attributes",
                            if full {
                                c.before.map_or(Json::Null, |(bo, br)| {
                                    store.observations[bo].routes()[br]
                                        .attribute_identity()
                                        .clone()
                                })
                            } else {
                                Json::Null
                            },
                        ),
                        (
                            "after_attributes",
                            if full {
                                c.route_index.map_or(Json::Null, |ri| {
                                    o.routes()[ri].attribute_identity().clone()
                                })
                            } else {
                                Json::Null
                            },
                        ),
                        (
                            "difference_semantics",
                            "complete_validated_attribute_identity_only".into(),
                        ),
                    ])
                }
                SourceItem::CapturedBoundary(ei) => Json::object([
                    ("ordinal", ordinal.into()),
                    ("kind", store.captured_source_events[ei].kind.name().into()),
                    ("difference", c.difference.into()),
                    ("native_partition_id", store.namespace.clone().into()),
                    ("reference", store.captured_source_events[ei].json()),
                ]),
                SourceItem::ImportedBoundary(ei) => {
                    let e = &store.imported_source_events[ei];
                    Json::object([
                        ("ordinal", ordinal.into()),
                        ("kind", format!("{:?}", e.kind).into()),
                        ("source_record_index", e.source_record_index.into()),
                        ("difference", c.difference.into()),
                        ("reference", e.reference.clone()),
                        ("source_id", e.source_id.clone().into()),
                        ("checkpoint_id", e.checkpoint_id.clone().into()),
                        (
                            "native_effect_classification",
                            if e.native_continuity.iter().any(|effect| effect.is_reset())
                                && e.native_continuity.iter().any(|effect| !effect.is_reset())
                            {
                                "applied_native_reset_and_gap"
                            } else if e.native_continuity.iter().any(|effect| effect.is_reset()) {
                                "applied_native_reset"
                            } else if !e.native_continuity.is_empty() {
                                "applied_native_gap"
                            } else {
                                "no_applied_native_effect"
                            }
                            .into(),
                        ),
                        (
                            "native_continuity",
                            Json::array(e.native_continuity.iter().map(|effect| effect.json())),
                        ),
                        (
                            "import_context",
                            e.context.as_ref().map_or(Json::Null, |c| c.json()),
                        ),
                        (
                            "continuity_cuts",
                            Json::array(e.continuity_cuts.iter().map(|cut| {
                                Json::object([
                                    ("context", cut.context.json()),
                                    ("record_id", cut.record_id.clone().into()),
                                    ("reason", cut.reason.clone().into()),
                                ])
                            })),
                        ),
                    ])
                }
            })),
        ),
        ("source_authenticated", false.into()),
        ("endpoint_state_claimed", false.into()),
        ("route_installation_claimed", false.into()),
    ]))
}

#[cfg(test)]
mod selector_metadata_tests {
    use super::super::query::{PrefixRelation, PrefixSelector, ReportedTimeWindow};
    use super::*;
    use crate::deep::bgp_import::ClockPolicy;

    #[test]
    fn unsupported_prefix_and_missing_time_availability_use_shared_typed_selectors() {
        let mut prefix = PrefixIdentity {
            afi: 25,
            safi: 1,
            length: 24,
            address: "203.0.113.0".into(),
        };
        let query = Query {
            prefix_selector: Some(
                PrefixSelector::parse("203.0.113.0/24", PrefixRelation::Exact).unwrap(),
            ),
            time_window: Some(ReportedTimeWindow {
                source: "native-source".into(),
                clock_policy: ClockPolicy::SourceLabel,
                clock_id: "native-clock".into(),
                start_ns: 0,
                end_ns: 100,
            }),
            ..Query::default()
        };
        let clock = ObservationClock {
            policy: ClockPolicy::SourceLabel,
            clock_id: Some("native-clock".into()),
            reported_uncertainty_ns: None,
        };
        assert_eq!(
            selector_metadata_uncertainties(&query, &prefix, "native-source", &clock, None),
            vec!["unsupported_prefix", "missing_reported_clock_or_time"]
        );
        prefix.afi = 1;
        assert!(selector_metadata_uncertainties(
            &query,
            &prefix,
            "native-source",
            &clock,
            Some(10)
        )
        .is_empty());
        assert!(
            selector_metadata_uncertainties(&query, &prefix, "other-source", &clock, None)
                .is_empty()
        );
        let wrong_clock = ObservationClock {
            clock_id: Some("other-clock".into()),
            ..clock.clone()
        };
        assert!(selector_metadata_uncertainties(
            &query,
            &prefix,
            "native-source",
            &wrong_clock,
            None
        )
        .is_empty());
        let wrong_policy = ObservationClock {
            policy: ClockPolicy::IngestionLabel,
            ..clock
        };
        assert!(selector_metadata_uncertainties(
            &query,
            &prefix,
            "native-source",
            &wrong_policy,
            None
        )
        .is_empty());
    }
}
