//! Selectors consume validated native observations. Legacy projections are output only.
use super::*;
pub use crate::deep::bgp_evidence::{AsnRole, AsnSelector};
use crate::deep::{bgp_import::ClockPolicy, bgp_state::RouteObservation};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrefixRelation {
    Exact,
    Contains,
    ContainedBy,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrefixSelector {
    address: IpAddr,
    length: u8,
    pub relation: PrefixRelation,
}
impl PrefixSelector {
    pub fn parse(value: &str, relation: PrefixRelation) -> Result<Self> {
        let (address, length) = value
            .rsplit_once('/')
            .ok_or_else(|| bad("bgp_query_prefix", 0, "CIDR required"))?;
        let ip: IpAddr = address
            .parse()
            .map_err(|_| bad("bgp_query_prefix", 0, "invalid IP"))?;
        let len: u8 = length
            .parse()
            .map_err(|_| bad("bgp_query_prefix", 0, "invalid length"))?;
        let maximum = if ip.is_ipv4() { 32 } else { 128 };
        if ip.to_string() != address
            || len > maximum
            || len.to_string() != length
            || masked(ip, len) != ip
        {
            return Err(bad(
                "bgp_query_prefix",
                0,
                "canonical network CIDR required",
            ));
        }
        Ok(Self {
            address: ip,
            length: len,
            relation,
        })
    }
    pub(crate) fn matches(&self, prefix: &PrefixIdentity) -> Option<bool> {
        let ip: IpAddr = prefix.address.parse().ok()?;
        if (prefix.afi == 1 && !ip.is_ipv4())
            || (prefix.afi == 2 && !ip.is_ipv6())
            || !matches!(prefix.afi, 1 | 2)
        {
            return None;
        }
        if self.address.is_ipv4() != ip.is_ipv4() {
            return Some(false);
        }
        Some(match self.relation {
            PrefixRelation::Exact => self.length == prefix.length && self.address == ip,
            PrefixRelation::Contains => {
                self.length <= prefix.length && masked(ip, self.length) == self.address
            }
            PrefixRelation::ContainedBy => {
                self.length >= prefix.length && masked(self.address, prefix.length) == ip
            }
        })
    }
}
fn masked(ip: IpAddr, length: u8) -> IpAddr {
    match ip {
        IpAddr::V4(a) => IpAddr::V4(
            (u32::from(a)
                & if length == 0 {
                    0
                } else {
                    u32::MAX << (32 - length)
                })
            .into(),
        ),
        IpAddr::V6(a) => IpAddr::V6(
            (u128::from(a)
                & if length == 0 {
                    0
                } else {
                    u128::MAX << (128 - length)
                })
            .into(),
        ),
    }
}
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum AttributeScope {
    #[default]
    CurrentEffective,
    AnyRetainedVersion,
    ObservationEvent,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReportedTimeWindow {
    pub source: String,
    pub clock_policy: ClockPolicy,
    pub clock_id: String,
    pub start_ns: i64,
    pub end_ns: i64,
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
    pub prefix_selector: Option<PrefixSelector>,
    pub asn: Option<AsnSelector>,
    pub community: Option<u32>,
    pub large_community: Option<[u32; 3]>,
    pub extended_community: Option<[u8; 8]>,
    pub next_hop: Option<IpAddr>,
    pub partition: Option<String>,
    pub generation: Option<u64>,
    pub direction: Option<u8>,
    pub path_id: Option<PathId>,
    pub lifecycle: Option<u64>,
    pub attribute_scope: Option<AttributeScope>,
    pub version_index: Option<usize>,
    pub occurrence_id: Option<String>,
    pub time_window: Option<ReportedTimeWindow>,
}
impl Query {
    pub fn validate(&self) -> Result<()> {
        for value in [
            &self.session,
            &self.prefix,
            &self.peer,
            &self.source,
            &self.checkpoint,
            &self.status,
            &self.partition,
            &self.occurrence_id,
        ]
        .into_iter()
        .flatten()
        {
            identity(value)?;
        }
        if self.afi == Some(0) || self.safi == Some(0) {
            return Err(bad("bgp_query_family", 0, "nonzero family required"));
        }
        if self.direction.is_some_and(|v| v > 1) || self.asn.is_some_and(|v| v.asn == 0) {
            return Err(bad("bgp_query_selector", 0, "invalid direction or ASN"));
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
            PrefixSelector::parse(prefix, PrefixRelation::Exact)?;
        }
        if self.prefix.is_some() && self.prefix_selector.is_some() {
            return Err(bad("bgp_query_prefix", 0, "conflicting prefix selectors"));
        }
        if let Some(window) = &self.time_window {
            identity(&window.source)?;
            identity(&window.clock_id)?;
            if window.clock_policy == ClockPolicy::Unknown
                || window.start_ns >= window.end_ns
                || self.source.as_ref().is_some_and(|s| s != &window.source)
            {
                return Err(bad(
                    "bgp_query_clock",
                    0,
                    "explicit comparable clock scope and nonempty half-open window required",
                ));
            }
        }
        if self.is_observation_event() && (self.status.is_some() || self.version_index.is_some()) {
            return Err(bad(
                "bgp_query_scope",
                0,
                "observation events have no native status or version index",
            ));
        }
        Ok(())
    }
    pub fn is_observation_event(&self) -> bool {
        self.attribute_scope == Some(AttributeScope::ObservationEvent)
    }
    pub(super) fn specification(&self) -> Json {
        Json::object([
            (
                "session",
                self.session.clone().map_or(Json::Null, Json::from),
            ),
            ("prefix", self.prefix.clone().map_or(Json::Null, Json::from)),
            ("afi", self.afi.map_or(Json::Null, Json::from)),
            ("safi", self.safi.map_or(Json::Null, Json::from)),
            ("peer", self.peer.clone().map_or(Json::Null, Json::from)),
            ("source", self.source.clone().map_or(Json::Null, Json::from)),
            (
                "checkpoint",
                self.checkpoint.clone().map_or(Json::Null, Json::from),
            ),
            ("status", self.status.clone().map_or(Json::Null, Json::from)),
            (
                "prefix_selector",
                self.prefix_selector.as_ref().map_or(Json::Null, |s| {
                    Json::object([
                        ("network", format!("{}/{}", s.address, s.length).into()),
                        (
                            "relation",
                            match s.relation {
                                PrefixRelation::Exact => "exact",
                                PrefixRelation::Contains => "contains",
                                PrefixRelation::ContainedBy => "contained_by",
                            }
                            .into(),
                        ),
                    ])
                }),
            ),
            (
                "asn",
                self.asn.map_or(Json::Null, |s| {
                    Json::object([("number", s.asn.into()), ("role", s.role.name().into())])
                }),
            ),
            ("community", self.community.map_or(Json::Null, Json::from)),
            (
                "large_community",
                self.large_community
                    .map_or(Json::Null, |v| Json::array(v.into_iter().map(Json::from))),
            ),
            (
                "extended_community",
                self.extended_community
                    .map_or(Json::Null, |v| sha256::hex(&v).into()),
            ),
            (
                "extended_community_semantics",
                "exact_raw_eight_bytes_no_interpretation_claim".into(),
            ),
            (
                "next_hop",
                self.next_hop.map_or(Json::Null, |v| v.to_string().into()),
            ),
            (
                "partition",
                self.partition.clone().map_or(Json::Null, Json::from),
            ),
            ("generation", self.generation.map_or(Json::Null, Json::from)),
            ("direction", self.direction.map_or(Json::Null, Json::from)),
            (
                "path_id",
                self.path_id.map_or(Json::Null, |v| match v {
                    PathId::Absent => "absent".into(),
                    PathId::Unknown => "unknown".into(),
                    PathId::Present(v) => v.into(),
                }),
            ),
            ("lifecycle", self.lifecycle.map_or(Json::Null, Json::from)),
            (
                "version_index",
                self.version_index.map_or(Json::Null, Json::from),
            ),
            (
                "occurrence_id",
                self.occurrence_id.clone().map_or(Json::Null, Json::from),
            ),
            (
                "reported_time_window",
                self.time_window.as_ref().map_or(Json::Null, |w| {
                    Json::object([
                        ("source", w.source.clone().into()),
                        (
                            "clock_policy",
                            match w.clock_policy {
                                ClockPolicy::Unknown => "unknown",
                                ClockPolicy::SourceLabel => "source_label",
                                ClockPolicy::IngestionLabel => "ingestion_label",
                            }
                            .into(),
                        ),
                        ("clock_id", w.clock_id.clone().into()),
                        ("start_ns", w.start_ns.to_string().into()),
                        ("end_ns", w.end_ns.to_string().into()),
                    ])
                }),
            ),
        ])
    }
    pub fn is_v2(&self) -> bool {
        self.prefix_selector.is_some()
            || self.asn.is_some()
            || self.community.is_some()
            || self.large_community.is_some()
            || self.extended_community.is_some()
            || self.next_hop.is_some()
            || self.partition.is_some()
            || self.generation.is_some()
            || self.direction.is_some()
            || self.path_id.is_some()
            || self.lifecycle.is_some()
            || self.attribute_scope.is_some()
            || self.version_index.is_some()
            || self.occurrence_id.is_some()
            || self.time_window.is_some()
    }
    fn has_attributes(&self) -> bool {
        self.asn.is_some()
            || self.community.is_some()
            || self.large_community.is_some()
            || self.extended_community.is_some()
            || self.next_hop.is_some()
            || self.version_index.is_some()
            || self.occurrence_id.is_some()
            || self.attribute_scope.is_some()
    }
    pub(super) fn matches(&self, row: &RouteRow, observations: &[Observation]) -> bool {
        self.evaluate(row, observations).matched
    }
    fn evaluate(&self, row: &RouteRow, observations: &[Observation]) -> Evaluation {
        let mut result = Evaluation::default();
        let key = &row.key;
        if self
            .session
            .as_ref()
            .is_some_and(|v| v != &key.scope.session)
            || self.afi.is_some_and(|v| v != key.family.afi)
            || self.safi.is_some_and(|v| v != key.family.safi)
            || self
                .source
                .as_ref()
                .is_some_and(|v| v != &key.scope.source.source_id)
            || self.status.as_ref().is_some_and(|v| v != row.status_name())
            || self
                .partition
                .as_ref()
                .is_some_and(|v| v != &key.scope.source.partition_id)
            || self.generation.is_some_and(|v| v != key.scope.generation)
        {
            return result;
        }
        if let Some(value) = &self.prefix {
            if value != &format!("{}/{}", key.prefix.address, key.prefix.length) {
                return result;
            }
        }
        if let Some(selector) = &self.prefix_selector {
            match selector.matches(&key.prefix) {
                Some(true) => {}
                Some(false) => return result,
                None => {
                    result.unknown.insert(Uncertainty::UnsupportedPrefix);
                }
            }
        }
        // Missing legacy fields remain v1 exclusions. V2 preserves the missing evidence.
        for (requested, actual, cause) in [
            (&self.peer, &key.scope.peer, Uncertainty::MissingPeer),
            (
                &self.checkpoint,
                &row.checkpoint,
                Uncertainty::MissingCheckpoint,
            ),
        ] {
            if let Some(requested) = requested {
                match actual {
                    Some(actual) if requested != actual => return result.excluded(),
                    None if self.is_v2() => {
                        result.unknown.insert(cause);
                    }
                    None => return result,
                    _ => {}
                }
            }
        }
        if let Some(value) = self.direction {
            match key.scope.direction {
                Some(actual) if value != actual => return result.excluded(),
                None => {
                    result.unknown.insert(Uncertainty::MissingDirection);
                }
                _ => {}
            }
        }
        if let Some(value) = self.lifecycle {
            match row.lifecycle {
                Some(actual) if value != actual => return result.excluded(),
                None => {
                    result.unknown.insert(Uncertainty::MissingLifecycle);
                }
                _ => {}
            }
        }
        if let Some(value) = self.path_id {
            if key.path_id == PathId::Unknown && value != PathId::Unknown {
                result.unknown.insert(Uncertainty::UnknownPathId);
            } else if value != key.path_id {
                return result.excluded();
            }
        }
        if !self.has_attributes() {
            if let Some(window) = &self.time_window {
                match time_match(
                    window,
                    &key.scope.source.source_id,
                    &row.clock,
                    row.observed_at_ns,
                ) {
                    Verdict::No => return result.excluded(),
                    Verdict::Unknown => {
                        result
                            .unknown
                            .insert(Uncertainty::MissingReportedClockOrTime);
                    }
                    Verdict::Yes => {}
                }
            }
            result.matched = result.unknown.is_empty();
            return result;
        }
        result.field_unknown.extend(result.unknown.iter().copied());
        let scope = self.attribute_scope.unwrap_or_default();
        if scope == AttributeScope::CurrentEffective
            && (!row.current
                || row
                    .selector_versions
                    .iter()
                    .filter(|v| v.disposition == VersionDisposition::Current)
                    .count()
                    != 1)
        {
            result
                .unknown
                .insert(Uncertainty::CurrentAttributesUnavailable);
            return result;
        }
        let mut eligible = false;
        let mut attributes_unknown = BTreeSet::new();
        for (vi, version) in row.selector_versions.iter().enumerate() {
            if self.version_index.is_some_and(|v| v != vi)
                || scope == AttributeScope::CurrentEffective
                    && version.disposition != VersionDisposition::Current
            {
                continue;
            }
            eligible = true;
            if version.occurrences.is_empty() {
                attributes_unknown.insert(Uncertainty::MissingVersionOccurrence);
            }
            for (oi, occurrence) in version.occurrences.iter().enumerate() {
                if self.occurrence_id.as_ref().is_some_and(|v| {
                    member(&occurrence.occurrence_ref, "source_occurrence_id").and_then(string)
                        != Some(v.as_str())
                }) {
                    continue;
                }
                let mut unknown = BTreeSet::new();
                if let Some(window) = &self.time_window {
                    match time_match(
                        window,
                        &key.scope.source.source_id,
                        &occurrence.clock,
                        occurrence.observed_at_ns,
                    ) {
                        Verdict::No => continue,
                        Verdict::Unknown => {
                            unknown.insert(Uncertainty::MissingReportedClockOrTime);
                        }
                        Verdict::Yes => {}
                    }
                }
                let Some(observation) = observations.get(occurrence.observation_index) else {
                    attributes_unknown.insert(Uncertainty::MissingVersionOccurrence);
                    continue;
                };
                let Some(route) = observation.routes().get(occurrence.route_index) else {
                    attributes_unknown.insert(Uncertainty::MissingVersionOccurrence);
                    continue;
                };
                let verdicts = self.attribute_verdicts(
                    route,
                    observation.normalized(),
                    occurrence.route_index,
                );
                for (cause, verdict) in &verdicts {
                    if *verdict == Verdict::Unknown {
                        unknown.insert(*cause);
                    }
                }
                result.field_unknown.extend(unknown.iter().copied());
                if verdicts.iter().any(|(_, v)| *v == Verdict::No) {
                    continue;
                }
                if unknown.is_empty() {
                    result.refs.push((vi, oi));
                } else {
                    attributes_unknown.extend(unknown);
                }
            }
        }
        if !eligible && self.version_index.is_none() {
            attributes_unknown.insert(if scope == AttributeScope::CurrentEffective {
                Uncertainty::CurrentAttributesUnavailable
            } else {
                Uncertainty::MissingVersionOccurrence
            });
        }
        result
            .field_unknown
            .extend(attributes_unknown.iter().copied());
        if result.refs.is_empty() {
            if attributes_unknown.is_empty() {
                result.unknown.clear();
            } else {
                result.unknown.extend(attributes_unknown);
            }
        } // an existential match resolves matching uncertainty, not field availability
        result.matched = !result.refs.is_empty() && result.unknown.is_empty();
        result
    }
    pub(crate) fn route_attribute_uncertainties(
        &self,
        route: &RouteObservation,
        normalized: &Json,
        route_index: usize,
    ) -> Vec<&'static str> {
        self.attribute_verdicts(route, normalized, route_index)
            .into_iter()
            .filter(|(_, v)| *v == Verdict::Unknown)
            .map(|(cause, _)| cause.name())
            .collect()
    }
    pub(crate) fn route_attributes_match(
        &self,
        route: &RouteObservation,
        normalized: &Json,
        route_index: usize,
    ) -> AttributeMatch {
        let verdicts = self.attribute_verdicts(route, normalized, route_index);
        if verdicts.iter().any(|(_, v)| *v == Verdict::No) {
            return AttributeMatch::NotMatched;
        }
        let unknown: Vec<_> = verdicts
            .into_iter()
            .filter(|(_, v)| *v == Verdict::Unknown)
            .map(|(cause, _)| cause.name())
            .collect();
        if unknown.is_empty() {
            AttributeMatch::Matched
        } else {
            AttributeMatch::Uncertain(unknown)
        }
    }
    fn occurrence_evaluation(
        &self,
        key: &RouteKey,
        lifecycle: Option<u64>,
        occurrence: &SelectorOccurrence,
        observations: &[Observation],
    ) -> Evaluation {
        let mut result = Evaluation::default();
        let Some(observation) = observations.get(occurrence.observation_index) else {
            result.unknown.insert(Uncertainty::MissingVersionOccurrence);
            return result;
        };
        let Some(route) = observation.routes().get(occurrence.route_index) else {
            result.unknown.insert(Uncertainty::MissingVersionOccurrence);
            return result;
        };
        if self
            .session
            .as_ref()
            .is_some_and(|v| v != &key.scope.session)
            || self
                .source
                .as_ref()
                .is_some_and(|v| v != &key.scope.source.source_id)
            || self
                .partition
                .as_ref()
                .is_some_and(|v| v != &key.scope.source.partition_id)
            || self.generation.is_some_and(|v| v != key.scope.generation)
            || self.afi.is_some_and(|v| v != key.family.afi)
            || self.safi.is_some_and(|v| v != key.family.safi)
        {
            return result;
        }
        if self
            .prefix
            .as_ref()
            .is_some_and(|v| v != &format!("{}/{}", key.prefix.address, key.prefix.length))
        {
            return result;
        }
        if let Some(selector) = &self.prefix_selector {
            match selector.matches(&key.prefix) {
                Some(false) => return result,
                None => {
                    result.unknown.insert(Uncertainty::UnsupportedPrefix);
                }
                _ => {}
            }
        }
        let checkpoint = observation
            .import_context()
            .map(|v| v.checkpoint_id.as_str());
        for (requested, actual, cause) in [
            (
                self.peer.as_deref(),
                key.scope.peer.as_deref(),
                Uncertainty::MissingPeer,
            ),
            (
                self.checkpoint.as_deref(),
                checkpoint,
                Uncertainty::MissingCheckpoint,
            ),
        ] {
            if let Some(requested) = requested {
                match actual {
                    Some(actual) if requested != actual => return result.excluded(),
                    None => {
                        result.unknown.insert(cause);
                    }
                    _ => {}
                }
            }
        }
        if let Some(value) = self.direction {
            match key.scope.direction {
                Some(actual) if value != actual => return result.excluded(),
                None => {
                    result.unknown.insert(Uncertainty::MissingDirection);
                }
                _ => {}
            }
        }
        if let Some(value) = self.lifecycle {
            match lifecycle {
                Some(actual) if value != actual => return result.excluded(),
                None => {
                    result.unknown.insert(Uncertainty::MissingLifecycle);
                }
                _ => {}
            }
        }
        if let Some(value) = self.path_id {
            if key.path_id == PathId::Unknown && value != PathId::Unknown {
                result.unknown.insert(Uncertainty::UnknownPathId);
            } else if value != key.path_id {
                return result.excluded();
            }
        }
        if self.occurrence_id.as_ref().is_some_and(|v| {
            member(&occurrence.occurrence_ref, "source_occurrence_id").and_then(string)
                != Some(v.as_str())
        }) {
            return result.excluded();
        }
        if let Some(window) = &self.time_window {
            match time_match(
                window,
                &key.scope.source.source_id,
                &occurrence.clock,
                occurrence.observed_at_ns,
            ) {
                Verdict::No => return result.excluded(),
                Verdict::Unknown => {
                    result
                        .unknown
                        .insert(Uncertainty::MissingReportedClockOrTime);
                }
                _ => {}
            }
        }
        let verdicts =
            self.attribute_verdicts(route, observation.normalized(), occurrence.route_index);
        for (cause, verdict) in &verdicts {
            if *verdict == Verdict::Unknown {
                result.unknown.insert(*cause);
            }
        }
        if verdicts.iter().any(|(_, v)| *v == Verdict::No) {
            return result.excluded();
        }
        result.matched = result.unknown.is_empty();
        result
    }
    fn attribute_verdicts(
        &self,
        route: &RouteObservation,
        normalized: &Json,
        route_index: usize,
    ) -> Vec<(Uncertainty, Verdict)> {
        let mut out = Vec::new();
        if let Some(selector) = self.asn {
            out.push((
                Uncertainty::UnresolvedAsn,
                match crate::deep::bgp_evidence::asn_route_match(route, selector) {
                    "matched" => Verdict::Yes,
                    "not_matched" => Verdict::No,
                    _ => Verdict::Unknown,
                },
            ));
        }
        // Community/next-hop predicates use validated producer fields. Complete semantic
        // identity is not required for exact raw-byte matching or independent fields.
        if let Some(value) = self.community {
            out.push((
                Uncertainty::UnresolvedStandardCommunity,
                community_match(route, value),
            ));
        }
        if let Some(value) = self.large_community {
            out.push((
                Uncertainty::UnresolvedLargeCommunity,
                large_match(route, value),
            ));
        }
        if let Some(value) = self.extended_community {
            out.push((
                Uncertainty::UnresolvedExtendedCommunity,
                extended_match(route, normalized, route_index, value),
            ));
        }
        if let Some(value) = self.next_hop {
            out.push((Uncertainty::UnresolvedNextHop, next_hop_match(route, value)));
        }
        out
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum AttributeMatch {
    Matched,
    NotMatched,
    Uncertain(Vec<&'static str>),
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Verdict {
    Yes,
    No,
    Unknown,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
enum Uncertainty {
    MissingPeer,
    MissingCheckpoint,
    MissingDirection,
    MissingLifecycle,
    UnknownPathId,
    UnsupportedPrefix,
    CurrentAttributesUnavailable,
    MissingVersionOccurrence,
    MissingReportedClockOrTime,
    UnresolvedAsn,
    UnresolvedStandardCommunity,
    UnresolvedLargeCommunity,
    UnresolvedExtendedCommunity,
    UnresolvedNextHop,
}
impl Uncertainty {
    fn name(self) -> &'static str {
        match self {
            Self::MissingPeer => "missing_peer",
            Self::MissingCheckpoint => "missing_checkpoint",
            Self::MissingDirection => "missing_direction",
            Self::MissingLifecycle => "missing_lifecycle",
            Self::UnknownPathId => "unknown_path_id",
            Self::UnsupportedPrefix => "unsupported_prefix",
            Self::CurrentAttributesUnavailable => "current_attributes_unavailable",
            Self::MissingVersionOccurrence => "missing_version_occurrence",
            Self::MissingReportedClockOrTime => "missing_reported_clock_or_time",
            Self::UnresolvedAsn => "unresolved_asn",
            Self::UnresolvedStandardCommunity => "unresolved_standard_community",
            Self::UnresolvedLargeCommunity => "unresolved_large_community",
            Self::UnresolvedExtendedCommunity => "unresolved_extended_community",
            Self::UnresolvedNextHop => "unresolved_next_hop",
        }
    }
}
#[derive(Default)]
struct Evaluation {
    matched: bool,
    refs: Vec<(usize, usize)>,
    unknown: BTreeSet<Uncertainty>,
    field_unknown: BTreeSet<Uncertainty>,
}
impl Evaluation {
    fn excluded(mut self) -> Self {
        self.field_unknown.extend(self.unknown.iter().copied());
        self.unknown.clear();
        self.refs.clear();
        self.matched = false;
        self
    }
    fn unavailable(&self) -> BTreeSet<Uncertainty> {
        self.unknown.union(&self.field_unknown).copied().collect()
    }
}
fn string(value: &Json) -> Option<&str> {
    if let Json::String(s) = value {
        Some(s)
    } else {
        None
    }
}
pub(crate) fn time_match(
    w: &ReportedTimeWindow,
    source: &str,
    clock: &ObservationClock,
    time: Option<i64>,
) -> Verdict {
    if w.source != source {
        return Verdict::No;
    }
    if (clock.policy != ClockPolicy::Unknown && w.clock_policy != clock.policy)
        || clock.clock_id.as_ref().is_some_and(|id| id != &w.clock_id)
    {
        return Verdict::No;
    }
    if clock.policy == ClockPolicy::Unknown || clock.clock_id.is_none() || time.is_none() {
        return Verdict::Unknown;
    }
    if time.is_some_and(|v| v >= w.start_ns && v < w.end_ns) {
        Verdict::Yes
    } else {
        Verdict::No
    }
}
pub(crate) fn complete(route: &RouteObservation) -> bool {
    !route.ambiguous_attributes()
        && member(route.semantic_identity(), "completeness").and_then(string) == Some("complete")
}

fn membership(items: Option<&Json>, predicate: impl Fn(&Json) -> bool) -> Verdict {
    match items {
        Some(Json::Array(values)) => {
            if values.iter().any(predicate) {
                Verdict::Yes
            } else {
                Verdict::No
            }
        }
        _ => Verdict::Unknown,
    }
}
fn community_match(route: &RouteObservation, value: u32) -> Verdict {
    if route.ambiguous_attributes() {
        return Verdict::Unknown;
    }
    membership(
        member(route.attributes(), "communities"),
        |v| matches!(v,Json::Number(n) if *n==u64::from(value)),
    )
}
fn effective_raw(route: &RouteObservation, code: u64) -> Option<&Json> {
    let Json::Array(values) = route.attribute_identity() else {
        return None;
    };
    values
        .iter()
        .find(|value| number(value, "type") == Some(code))
        .filter(|value| {
            member(value, "disposition").and_then(string) == Some("accept_evidence_only")
        })
}
fn large_match(route: &RouteObservation, value: [u32; 3]) -> Verdict {
    if route.ambiguous_attributes() {
        return Verdict::Unknown;
    }
    if let Some(raw) = effective_raw(route, 32) {
        return membership(
            member(raw, "decoded"),
            |v| matches!(v,Json::Array(xs) if xs.len()==3 && xs.iter().zip(value).all(|(n,v)|matches!(n,Json::Number(n) if *n==u64::from(v)))),
        );
    }
    if let Some(values) = member(route.attributes(), "large_communities") {
        return membership(
            Some(values),
            |v| matches!(v,Json::Array(xs) if xs.len()==3 && xs.iter().zip(value).all(|(n,v)|matches!(n,Json::Number(n) if *n==u64::from(v)))),
        );
    }
    if complete(route) {
        Verdict::No
    } else {
        Verdict::Unknown
    }
}
fn extended_match(
    route: &RouteObservation,
    normalized: &Json,
    route_index: usize,
    value: [u8; 8],
) -> Verdict {
    let raw_route = member(normalized, "routes").and_then(|v| {
        if let Json::Array(v) = v {
            v.get(route_index)
        } else {
            None
        }
    });
    let ranges = raw_route
        .and_then(|v| member(v, "attribute_ranges"))
        .and_then(|v| {
            if let Json::Array(xs) = v {
                Some(xs.as_slice())
            } else {
                None
            }
        })
        .filter(|v| !v.is_empty())
        .or_else(|| {
            raw_route
                .and_then(|v| member(v, "imported_attribute_occurrences"))
                .and_then(|v| member(v, "occurrences"))
                .and_then(|v| {
                    if let Json::Array(xs) = v {
                        Some(xs.as_slice())
                    } else {
                        None
                    }
                })
        });
    let raw = ranges
        .and_then(|ranges| ranges.iter().find(|v| number(v, "type") == Some(16)))
        .filter(|v| member(v, "disposition").and_then(string) == Some("accept_evidence_only"));
    let Some(raw) = raw else {
        return if complete(route) {
            Verdict::No
        } else {
            Verdict::Unknown
        };
    };
    let Some(hex) = member(raw, "value_hex").and_then(string) else {
        return Verdict::Unknown;
    };
    let expected = sha256::hex(&value);
    if hex.len() % 16 != 0 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Verdict::Unknown;
    }
    if hex
        .as_bytes()
        .chunks_exact(16)
        .any(|c| c == expected.as_bytes())
    {
        Verdict::Yes
    } else {
        Verdict::No
    }
}
fn next_hop_match(route: &RouteObservation, value: IpAddr) -> Verdict {
    if route.ambiguous_attributes() {
        return Verdict::Unknown;
    }
    let Some(text) = member(route.attributes(), "next_hop").and_then(string) else {
        return Verdict::Unknown;
    };
    let mut found = false;
    for part in text.split(',') {
        let Ok(ip) = part.parse::<IpAddr>() else {
            return Verdict::Unknown;
        };
        if ip.to_string() != part {
            return Verdict::Unknown;
        }
        found |= ip == value;
    }
    if found {
        Verdict::Yes
    } else {
        Verdict::No
    }
}

fn matched_json(
    row: &RouteRow,
    index: usize,
    version: &SelectorVersion,
    occurrence: Option<&Json>,
) -> Json {
    Json::object([
        ("row_id", row.id.clone().into()),
        ("version_index", index.into()),
        (
            "attribute_identity",
            version.attribute_identity.clone().into(),
        ),
        (
            "disposition",
            format!("{:?}", version.disposition).to_lowercase().into(),
        ),
        ("occurrence", occurrence.cloned().unwrap_or(Json::Null)),
    ])
}
fn observation_match_json(reference: Option<&Json>, semantics_unknown: bool) -> Json {
    Json::object([
        ("occurrence", reference.cloned().unwrap_or(Json::Null)),
        ("semantics_unknown", semantics_unknown.into()),
        ("raw_extended_community_semantics", "unknown".into()),
        ("native_version_claimed", false.into()),
    ])
}
impl VerifiedStore {
    fn observation_query_v2(&self, query: &Query, limits: &Limits) -> Result<String> {
        let coverage = self.selector_coverage(query, limits)?;
        let empty = Json::object([
            ("schema", "pcap-evidence.bgp.persisted-query.v2".into()),
            ("store", self.reference()),
            ("routes", Json::array([])),
            ("attribute_matches", Json::array([])),
            ("observation_matches", Json::array([])),
            ("selectors", query.specification()),
            ("selector_coverage", coverage.clone()),
            ("endpoint_state_claimed", false.into()),
        ]);
        let cap = limits
            .output_bytes
            .min(limits.retained_bytes)
            .min(limits.work);
        let mut bytes = empty.encoded_len_bounded(cap)?;
        let mut nodes = 0usize;
        let mut count = 0usize;
        inspect_borrowed(&empty, 0, &mut nodes, limits)?;
        let mut spans = reference_spans(&empty);
        for (key, life, occurrence) in self.source_route_occurrences() {
            if !query
                .occurrence_evaluation(key, life, occurrence, &self.observations)
                .matched
            {
                continue;
            }
            count += 1;
            if count > limits.elements {
                return Err(Error::limit("bgp_persisted_elements"));
            }
            let route =
                &self.observations[occurrence.observation_index].routes()[occurrence.route_index];
            let base = observation_match_json(None, !complete(route));
            inspect_borrowed(&base, 2, &mut nodes, limits)?;
            inspect_borrowed(&occurrence.occurrence_ref, 3, &mut nodes, limits)?;
            spans = spans
                .checked_add(reference_spans(&occurrence.occurrence_ref))
                .ok_or_else(|| Error::limit("bgp_query_spans"))?;
            if spans > limits.spans {
                return Err(Error::limit("bgp_query_spans"));
            }
            bytes = bytes
                .checked_add(base.encoded_len_bounded(cap)?.saturating_sub(4))
                .and_then(|v| {
                    v.checked_add(occurrence.occurrence_ref.encoded_len_bounded(cap).ok()?)
                })
                .ok_or_else(|| Error::limit("bgp_persisted_output"))?;
            guard_projection(bytes, limits)?;
        }
        bytes = bytes
            .checked_add(count.saturating_sub(1))
            .ok_or_else(|| Error::limit("bgp_persisted_output"))?;
        guard_projection(bytes, limits)?;
        let mut events = Vec::with_capacity(count);
        for (key, life, occurrence) in self.source_route_occurrences() {
            if !query
                .occurrence_evaluation(key, life, occurrence, &self.observations)
                .matched
            {
                continue;
            }
            let route =
                &self.observations[occurrence.observation_index].routes()[occurrence.route_index];
            events.push(observation_match_json(
                Some(&occurrence.occurrence_ref),
                !complete(route),
            ));
        }
        bounded_output(
            Json::object([
                ("schema", "pcap-evidence.bgp.persisted-query.v2".into()),
                ("store", self.reference()),
                ("routes", Json::array([])),
                ("attribute_matches", Json::array([])),
                ("observation_matches", Json::Array(events)),
                ("selectors", query.specification()),
                ("selector_coverage", coverage),
                ("endpoint_state_claimed", false.into()),
            ]),
            limits,
        )
    }
    pub(super) fn query_v2(&self, query: &Query, limits: &Limits) -> Result<String> {
        query.validate()?;
        limits.validate()?;
        preflight_envelope(self, limits)?;
        if query.is_observation_event() {
            return self.observation_query_v2(query, limits);
        }
        let coverage = self.selector_coverage(query, limits)?;
        let empty = Json::object([
            ("schema", "pcap-evidence.bgp.persisted-query.v2".into()),
            ("store", self.reference()),
            ("routes", Json::array([])),
            ("selector_coverage", coverage.clone()),
            ("selectors", query.specification()),
            ("attribute_matches", Json::array([])),
            ("observation_matches", Json::array([])),
            ("endpoint_state_claimed", false.into()),
        ]);
        let cap = limits
            .output_bytes
            .min(limits.retained_bytes)
            .min(limits.work);
        let mut bytes = empty.encoded_len_bounded(cap)?;
        let mut nodes = 0usize;
        inspect_borrowed(&empty, 0, &mut nodes, limits)?;
        let mut spans = reference_spans(&empty);
        let mut row_count = 0usize;
        let mut match_count = 0usize;
        // Measure all borrowed evidence and the entire aggregate before cloning.
        for row in &self.rows {
            let evaluation = query.evaluate(row, &self.observations);
            if !evaluation.matched {
                continue;
            }
            row_count += 1;
            if row_count > limits.elements {
                return Err(Error::limit("bgp_persisted_elements"));
            }
            bytes = bytes
                .checked_add(row.evidence_encoded_len(cap)?)
                .ok_or_else(|| Error::limit("bgp_persisted_output"))?;
            row.inspect_evidence(2, &mut nodes, limits)?;
            spans = spans
                .checked_add(row.evidence_spans())
                .ok_or_else(|| Error::limit("bgp_query_spans"))?;
            if spans > limits.spans {
                return Err(Error::limit("bgp_query_spans"));
            }
            for (vi, oi) in evaluation.refs {
                match_count += 1;
                if match_count > limits.elements {
                    return Err(Error::limit("bgp_persisted_elements"));
                }
                let version = &row.selector_versions[vi];
                let occurrence = &version.occurrences[oi].occurrence_ref;
                inspect_borrowed(occurrence, 3, &mut nodes, limits)?;
                spans = spans
                    .checked_add(reference_spans(occurrence))
                    .ok_or_else(|| Error::limit("bgp_query_spans"))?;
                if spans > limits.spans {
                    return Err(Error::limit("bgp_query_spans"));
                }
                let base = matched_json(row, vi, version, None);
                inspect_borrowed(&base, 2, &mut nodes, limits)?;
                bytes = bytes
                    .checked_add(base.encoded_len_bounded(cap)?.saturating_sub(4))
                    .and_then(|b| b.checked_add(occurrence.encoded_len_bounded(cap).ok()?))
                    .ok_or_else(|| Error::limit("bgp_persisted_output"))?;
            }
            guard_projection(bytes, limits)?;
        }
        bytes = bytes
            .checked_add(row_count.saturating_sub(1))
            .and_then(|b| b.checked_add(match_count.saturating_sub(1)))
            .ok_or_else(|| Error::limit("bgp_persisted_output"))?;
        guard_projection(bytes, limits)?;
        let mut routes = Vec::with_capacity(row_count);
        let mut matches = Vec::with_capacity(match_count);
        for row in &self.rows {
            let evaluation = query.evaluate(row, &self.observations);
            if !evaluation.matched {
                continue;
            }
            routes.push(row.evidence_json());
            for (vi, oi) in evaluation.refs {
                let version = &row.selector_versions[vi];
                matches.push(matched_json(
                    row,
                    vi,
                    version,
                    Some(&version.occurrences[oi].occurrence_ref),
                ));
            }
        }
        bounded_output(
            Json::object([
                ("schema", "pcap-evidence.bgp.persisted-query.v2".into()),
                ("store", self.reference()),
                ("routes", Json::Array(routes)),
                ("selector_coverage", coverage),
                ("selectors", query.specification()),
                ("attribute_matches", Json::Array(matches)),
                ("observation_matches", Json::array([])),
                ("endpoint_state_claimed", false.into()),
            ]),
            limits,
        )
    }
    pub(super) fn selector_coverage(&self, query: &Query, limits: &Limits) -> Result<Json> {
        let mut counts: BTreeMap<Uncertainty, usize> = BTreeMap::new();
        let mut availability_counts: BTreeMap<Uncertainty, usize> = BTreeMap::new();
        let mut availability_witnesses = Vec::new();
        let mut availability_rows = 0usize;
        let mut witnesses = Vec::new();
        let mut unknown_rows = 0usize;
        let mut matched = 0usize;
        let cap = limits.elements.min(64);
        let work = self
            .rows
            .iter()
            .try_fold(0usize, |n, r| {
                n.checked_add(
                    1 + r
                        .selector_versions
                        .iter()
                        .map(|v| v.occurrences.len())
                        .sum::<usize>(),
                )
            })
            .ok_or_else(|| Error::limit("bgp_query_work"))?;
        if work > limits.work {
            return Err(Error::limit("bgp_query_work"));
        }
        let total = if query.is_observation_event() {
            self.source_route_occurrences().count()
        } else {
            self.rows.len()
        };
        if total > limits.elements || total > limits.work {
            return Err(Error::limit("bgp_query_work"));
        }
        let entries: Box<dyn Iterator<Item = (String, Evaluation)> + '_> =
            if query.is_observation_event() {
                Box::new(self.source_route_occurrences().map(|(key, life, occ)| {
                    (
                        format!("source-route:{}:{}", occ.observation_index, occ.route_index),
                        query.occurrence_evaluation(key, life, occ, &self.observations),
                    )
                }))
            } else {
                Box::new(
                    self.rows
                        .iter()
                        .map(|row| (row.id.clone(), query.evaluate(row, &self.observations))),
                )
            };
        for (id, e) in entries {
            matched += usize::from(e.matched);
            let unavailable = e.unavailable();
            if !unavailable.is_empty() {
                availability_rows += 1;
                for cause in &unavailable {
                    *availability_counts.entry(*cause).or_default() += 1;
                }
                if availability_witnesses.len() < cap {
                    availability_witnesses.push(Json::object([
                        ("row_id", id.clone().into()),
                        (
                            "matching_disposition",
                            if e.matched {
                                "matched"
                            } else if e.unknown.is_empty() {
                                "excluded_by_known_predicate"
                            } else {
                                "uncertain"
                            }
                            .into(),
                        ),
                        (
                            "unavailable_fields",
                            Json::array(unavailable.into_iter().map(|v| v.name().into())),
                        ),
                    ]));
                }
            }
            if e.unknown.is_empty() {
                continue;
            }
            unknown_rows += 1;
            for cause in &e.unknown {
                *counts.entry(*cause).or_default() += 1;
            }
            if witnesses.len() < cap {
                witnesses.push(Json::object([
                    ("row_id", id.clone().into()),
                    (
                        "uncertainties",
                        Json::array(e.unknown.into_iter().map(|v| v.name().into())),
                    ),
                ]));
            }
        }
        Ok(Json::object([
            ("coverage_scope", "selector_fields".into()),
            ("source_coverage", "unknown".into()),
            ("field_unavailable_rows", availability_rows.into()),
            (
                "field_availability_unknown_counts",
                Json::array(availability_counts.into_iter().map(|(cause, count)| {
                    Json::object([
                        ("field_uncertainty", cause.name().into()),
                        ("rows", count.into()),
                    ])
                })),
            ),
            (
                "field_availability_witnesses",
                Json::Array(availability_witnesses),
            ),
            (
                "field_availability_witnesses_omitted",
                availability_rows.saturating_sub(cap).into(),
            ),
            ("matched_rows", matched.into()),
            ("selector_uncertain_rows", unknown_rows.into()),
            ("excluded_rows", (total - matched - unknown_rows).into()),
            (
                "uncertainty_counts",
                Json::array(counts.into_iter().map(|(cause, count)| {
                    Json::object([
                        ("selector_uncertainty", cause.name().into()),
                        ("rows", count.into()),
                    ])
                })),
            ),
            ("row_witnesses", Json::Array(witnesses)),
            (
                "row_witnesses_omitted",
                unknown_rows.saturating_sub(cap).into(),
            ),
            (
                "reported_time_semantics",
                "reported_label_half_open_window_no_accuracy_claim".into(),
            ),
            (
                "attribute_scope",
                match query.attribute_scope.unwrap_or_default() {
                    AttributeScope::CurrentEffective => "current_effective",
                    AttributeScope::AnyRetainedVersion => "any_retained_version",
                    AttributeScope::ObservationEvent => "observation_event",
                }
                .into(),
            ),
        ]))
    }
}

#[cfg(test)]
mod clock_window_tests {
    use super::*;

    #[test]
    fn known_clock_scope_mismatch_excludes_before_missing_time() {
        let window = ReportedTimeWindow {
            source: "source-a".into(),
            clock_policy: ClockPolicy::SourceLabel,
            clock_id: "clock-a".into(),
            start_ns: -10,
            end_ns: 0,
        };
        let clock = ObservationClock {
            policy: ClockPolicy::SourceLabel,
            clock_id: Some("clock-a".into()),
            reported_uncertainty_ns: None,
        };
        assert_eq!(
            time_match(&window, "source-a", &clock, Some(-10)),
            Verdict::Yes
        );
        assert_eq!(
            time_match(&window, "source-a", &clock, Some(0)),
            Verdict::No
        );
        assert_eq!(
            time_match(&window, "source-a", &clock, None),
            Verdict::Unknown
        );
        let wrong_id = ObservationClock {
            clock_id: Some("clock-b".into()),
            ..clock.clone()
        };
        assert_eq!(
            time_match(&window, "source-a", &wrong_id, None),
            Verdict::No
        );
        let wrong_policy = ObservationClock {
            policy: ClockPolicy::IngestionLabel,
            ..clock
        };
        assert_eq!(
            time_match(&window, "source-a", &wrong_policy, None),
            Verdict::No
        );
        assert_eq!(
            time_match(&window, "source-b", &ObservationClock::default(), None),
            Verdict::No
        );
    }
}
