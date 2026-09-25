//! Configured offline ranking of Adj-RIB-In candidates. A selection is an
//! explanation of supplied evidence, never an installed or propagated route.
use super::bgp_rib::{validate_route_key, RouteKey, RouteStatus};
use super::bgp_session::{PartitionKind, StaleKind};
use super::model::{bad, Limits};
use pcap_evidence::{json::Json, sha256, Error, Result};
use std::collections::BTreeMap;
use std::io::Write;
use std::mem::size_of;
use std::net::{IpAddr, Ipv4Addr};

pub const SCHEMA: &str = "pcap-evidence.bgp.policy-candidate.v1";
pub const RESULT_SCHEMA: &str = "pcap-evidence.bgp.policy-result.v1";
const STORE_BINDING_UNAVAILABLE: &str = "not_provided_by_policy_api";
pub const ORDER: [&str; 10] = [
    "local_preference",
    "locally_originated",
    "as_path_length",
    "origin",
    "med",
    "ebgp_over_ibgp",
    "igp_metric",
    "age",
    "router_id",
    "neighbor_address",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MedRule {
    SameNeighborAs,
    CompareAll,
    Skip,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AgeRule {
    SameClock,
    Skip,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyConfig {
    /// Exact owner/configuration witness. It does not authenticate the router.
    pub provenance: String,
    /// Caller-declared comparison context; never derived from peer addresses.
    pub comparison_context: String,
    pub missing_local_preference: Option<u32>,
    pub med_rule: Option<MedRule>,
    pub age_rule: Option<AgeRule>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgeEvidence {
    pub clock_id: String,
    pub observed_order: u64,
}

/// MED evidence distinguishes a wire/configured absence (which compares as
/// zero) from unavailable evidence, represented by `None` on the input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MedEvidence {
    Absent,
    Present(u32),
}
impl MedEvidence {
    fn value(self) -> u32 {
        match self {
            Self::Absent => 0,
            Self::Present(value) => value,
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct BestPathInputs {
    pub local_preference: Option<u32>,
    pub locally_originated: Option<bool>,
    pub as_path_length: Option<u32>,
    pub origin: Option<u8>,
    pub med: Option<MedEvidence>,
    pub neighboring_as: Option<u32>,
    pub ebgp: Option<bool>,
    pub igp_metric: Option<u32>,
    pub age: Option<AgeEvidence>,
    pub router_id: Option<Ipv4Addr>,
    pub neighbor_address: Option<IpAddr>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyCandidate {
    pub id: String,
    pub key: RouteKey,
    pub comparison_context: String,
    pub status: RouteStatus,
    pub inputs: BestPathInputs,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StepResult {
    Left,
    Right,
    Equal,
    Skipped,
    Unresolved,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TraceStep {
    pub criterion: &'static str,
    pub left: Option<String>,
    pub right: Option<String>,
    pub result: StepResult,
    pub reason: &'static str,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Comparison {
    pub left_id: String,
    pub right_id: String,
    pub steps: Vec<TraceStep>,
    pub result: StepResult,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyResult {
    pub selected: Option<String>,
    pub unresolved: Vec<String>,
    pub excluded: Vec<(String, RouteStatus)>,
    pub comparisons: Vec<Comparison>,
    pub config_provenance: String,
    /// SHA-256 of canonical policy configuration, not an authentication claim.
    pub config_fingerprint_sha256: String,
    /// SHA-256 of ID-sorted canonical candidates, including partition/session.
    pub candidate_set_fingerprint_sha256: String,
    pub endpoint_rib_established: bool,
    pub propagated_route_established: bool,
}

impl PolicyResult {
    /// Exact canonical compact-JSON byte length without a result-sized JSON
    /// tree or output string.
    pub fn encoded_len(&self, limit: usize) -> Result<usize> {
        render_canonical(self, limit, None)
    }

    /// Versioned canonical JSON, admitted by exact encoded size before the
    /// output buffer is allocated or populated.
    /// The policy API cannot bind to an authenticated/exact candidate store.
    pub fn encode_canonical(&self, limits: &Limits) -> Result<String> {
        limits.validate()?;
        let limit = limits.output_bytes.min(limits.retained_bytes);
        let size = self.encoded_len(limit)?;
        let mut output = String::new();
        output
            .try_reserve_exact(size)
            .map_err(|_| Error::limit("bgp_policy_output_allocation"))?;
        render_canonical(self, limit, Some(&mut output))?;
        debug_assert_eq!(output.len(), size);
        Ok(output)
    }

    /// Append the complete canonical document to `writer` only after bounded
    /// encoding succeeds. A size-cap failure leaves the destination untouched.
    pub fn write_canonical<W: Write>(&self, writer: &mut W, limits: &Limits) -> Result<usize> {
        let encoded = self.encode_canonical(limits)?;
        writer.write_all(encoded.as_bytes()).map_err(Error::io)?;
        Ok(encoded.len())
    }
}

/// Every pair is evaluated in ID order, so caller permutations cannot alter the
/// trace. Any missing/incomparable required evidence blocks the whole decision.
pub fn evaluate(
    config: &PolicyConfig,
    candidates: &[PolicyCandidate],
    limits: &Limits,
) -> Result<PolicyResult> {
    limits.validate()?;
    check_text(&config.provenance, limits)?;
    check_text(&config.comparison_context, limits)?;
    if candidates.len() > limits.elements {
        return Err(Error::limit("bgp_policy_candidates"));
    }
    let mut ordered: BTreeMap<&str, &PolicyCandidate> = BTreeMap::new();
    for c in candidates {
        check_text(&c.id, limits)?;
        check_text(&c.comparison_context, limits)?;
        for value in [
            &c.key.scope.source.source_id,
            &c.key.scope.source.partition_id,
            &c.key.scope.session,
            &c.key.prefix.address,
        ] {
            check_text(value, limits)?;
        }
        if let Some(peer) = &c.key.scope.peer {
            check_text(peer, limits)?;
        }
        if let Some(age) = &c.inputs.age {
            check_text(&age.clock_id, limits)?;
        }
        validate_route_key(&c.key, limits, c.status == RouteStatus::Active)?;
        if ordered.insert(&c.id, c).is_some() {
            return Err(bad("bgp_policy_identity", 0, "duplicate candidate id"));
        }
    }
    let identity_limit = limits
        .input_bytes
        .min(limits.retained_bytes)
        .min(limits.work);
    let (config_fingerprint_sha256, config_identity_bytes) =
        fingerprint_config(config, identity_limit)?;
    let candidate_identity_limit = identity_limit
        .checked_sub(config_identity_bytes)
        .ok_or_else(|| Error::limit("bgp_policy_identity_budget"))?;
    let (candidate_set_fingerprint_sha256, candidate_identity_bytes) =
        fingerprint_candidates(ordered.values().copied(), candidate_identity_limit)?;
    let identity_bytes = config_identity_bytes
        .checked_add(candidate_identity_bytes)
        .ok_or_else(|| Error::limit("bgp_policy_identity_budget"))?;
    if identity_bytes > limits.retained_bytes || identity_bytes > limits.work {
        return Err(Error::limit("bgp_policy_identity_budget"));
    }
    let mut result = PolicyResult {
        selected: None,
        unresolved: Vec::new(),
        excluded: Vec::new(),
        comparisons: Vec::new(),
        config_provenance: config.provenance.clone(),
        config_fingerprint_sha256,
        candidate_set_fingerprint_sha256,
        endpoint_rib_established: false,
        propagated_route_established: false,
    };
    let mut active = Vec::new();
    for c in ordered.values().copied() {
        if c.status != RouteStatus::Active {
            result.excluded.push((c.id.clone(), c.status));
        } else {
            active.push(c);
        }
    }
    if active.is_empty() {
        result.unresolved.push("no_active_candidates".into());
    }
    // Admit quadratic trace growth before allocating a pair or step. This is
    // a logical retained-byte estimate, not an allocator/RSS guarantee.
    let active_count = active.len();
    let pair_count = active_count
        .checked_mul(active_count.saturating_sub(1))
        .and_then(|n| n.checked_div(2))
        .ok_or_else(|| Error::limit("bgp_policy_trace_budget"))?;
    let id_bytes = active.iter().try_fold(0usize, |sum, candidate| {
        sum.checked_add(candidate.id.len())
            .ok_or_else(|| Error::limit("bgp_policy_trace_budget"))
    })?;
    let id_bytes_per_pair = id_bytes
        .checked_mul(active_count.saturating_sub(1))
        .ok_or_else(|| Error::limit("bgp_policy_trace_budget"))?;
    let per_pair_retained = size_of::<Comparison>()
        .checked_add(size_of::<String>() + 64)
        .and_then(|n| {
            size_of::<TraceStep>()
                .checked_add(2 * 39)
                .and_then(|per_step| per_step.checked_mul(ORDER.len()))
                .and_then(|steps| n.checked_add(steps))
        })
        .ok_or_else(|| Error::limit("bgp_policy_trace_budget"))?;
    let trace_bytes = pair_count
        .checked_mul(per_pair_retained)
        .and_then(|n| {
            id_bytes_per_pair
                .checked_mul(2)
                .and_then(|ids| n.checked_add(ids))
        })
        .ok_or_else(|| Error::limit("bgp_policy_trace_budget"))?;
    let trace_work = pair_count
        .checked_mul(ORDER.len())
        .and_then(|n| n.checked_mul(64))
        .and_then(|n| {
            id_bytes_per_pair
                .checked_mul(2)
                .and_then(|ids| n.checked_add(ids))
        })
        .ok_or_else(|| Error::limit("bgp_policy_trace_budget"))?;
    // Compare once to measure the exact encoded trace and decide the winner,
    // then recompute only after all budgets pass to retain the full trace.
    let trace_work = trace_work
        .checked_mul(2)
        .ok_or_else(|| Error::limit("bgp_policy_trace_budget"))?;
    let preflight_work = identity_bytes
        .checked_add(trace_work)
        .ok_or_else(|| Error::limit("bgp_policy_trace_budget"))?;
    if preflight_work > limits.work || trace_bytes > limits.retained_bytes {
        return Err(Error::limit("bgp_policy_trace_budget"));
    }
    if let Some(first) = active.first() {
        for c in &active {
            if c.comparison_context != config.comparison_context
                || c.key.scope.source != first.key.scope.source
                || c.key.scope.direction != first.key.scope.direction
                || c.key.prefix != first.key.prefix
                || c.key.family != first.key.family
            {
                result
                    .unresolved
                    .push(format!("{}:comparison_scope_unproven", c.id));
            }
        }
    }
    let mut win_counts: BTreeMap<&str, usize> = BTreeMap::new();
    let output_limit = limits.output_bytes.min(limits.retained_bytes);
    let mut comparison_array_content_bytes = 0usize;
    let mut compared_pairs = 0usize;
    for (i, left) in active.iter().enumerate() {
        for right in active.iter().skip(i + 1) {
            let comparison = compare(left, right, config);
            if compared_pairs != 0 {
                comparison_array_content_bytes = comparison_array_content_bytes
                    .checked_add(1)
                    .ok_or_else(|| Error::limit("bgp_policy_output_bytes"))?;
            }
            let remaining = output_limit
                .checked_sub(comparison_array_content_bytes)
                .ok_or_else(|| Error::limit("bgp_policy_output_bytes"))?;
            let comparison_bytes = comparison_json(&comparison)
                .encoded_len_bounded(remaining)
                .map_err(|_| Error::limit("bgp_policy_output_bytes"))?;
            comparison_array_content_bytes = comparison_array_content_bytes
                .checked_add(comparison_bytes)
                .ok_or_else(|| Error::limit("bgp_policy_output_bytes"))?;
            compared_pairs += 1;
            match comparison.result {
                StepResult::Left => {
                    *win_counts.entry(&left.id).or_default() += 1;
                }
                StepResult::Right => {
                    *win_counts.entry(&right.id).or_default() += 1;
                }
                _ => {
                    let criterion = comparison
                        .steps
                        .iter()
                        .find(|step| step.result == StepResult::Unresolved)
                        .map_or("all_criteria_equal", |step| step.criterion);
                    result.unresolved.push(format!(
                        "{}:{}:incomparable_at_{criterion}",
                        left.id, right.id
                    ));
                }
            }
        }
    }
    if result.unresolved.is_empty() {
        let dominators: Vec<_> = active
            .iter()
            .filter(|c| win_counts.get(c.id.as_str()).copied().unwrap_or(0) == active.len() - 1)
            .collect();
        if dominators.len() == 1 {
            result.selected = Some(dominators[0].id.clone());
        } else {
            result.unresolved.push("no_unique_pairwise_winner".into());
        }
    }
    debug_assert_eq!(compared_pairs, pair_count);
    // `result` still has an empty comparisons array. Replace its two bracket
    // bytes with the streamed array's two brackets plus exact item/comma sizes.
    let empty_result_bytes = result.encoded_len(output_limit)?;
    let size = empty_result_bytes
        .checked_sub(2)
        .and_then(|n| n.checked_add(2))
        .and_then(|n| n.checked_add(comparison_array_content_bytes))
        .ok_or_else(|| Error::limit("bgp_policy_output_bytes"))?;
    if size > output_limit {
        return Err(Error::limit("bgp_policy_output_bytes"));
    }
    let total_work = preflight_work
        .checked_add(size)
        .ok_or_else(|| Error::limit("bgp_policy_budget"))?;
    let retained = trace_bytes
        .checked_add(identity_bytes)
        .and_then(|n| n.checked_add(size))
        .ok_or_else(|| Error::limit("bgp_policy_budget"))?;
    if total_work > limits.work || retained > limits.retained_bytes {
        return Err(Error::limit("bgp_policy_budget"));
    }
    result
        .comparisons
        .try_reserve_exact(pair_count)
        .map_err(|_| Error::limit("bgp_policy_trace_allocation"))?;
    for (i, left) in active.iter().enumerate() {
        for right in active.iter().skip(i + 1) {
            result.comparisons.push(compare(left, right, config));
        }
    }
    Ok(result)
}

fn fingerprint_config(config: &PolicyConfig, limit: usize) -> Result<(String, usize)> {
    let identity = config_identity_json(config);
    let size = identity.encoded_len_bounded(limit)?;
    let encoded = identity.encode_bounded(size)?;
    Ok((sha256::hex(&sha256::digest(encoded.as_bytes())), size))
}

fn fingerprint_candidates<'a>(
    candidates: impl Iterator<Item = &'a PolicyCandidate>,
    limit: usize,
) -> Result<(String, usize)> {
    let mut digest = sha256::Sha256::new();
    digest.update(b"pcap-evidence.bgp.policy-candidate-set.v1\0");
    let mut used = 0usize;
    for candidate in candidates {
        let identity = candidate_identity_json(candidate);
        let remaining = limit
            .checked_sub(used)
            .ok_or_else(|| Error::limit("bgp_policy_identity_budget"))?;
        let json_limit = remaining
            .checked_sub(size_of::<u64>())
            .ok_or_else(|| Error::limit("bgp_policy_identity_budget"))?;
        let size = identity.encoded_len_bounded(json_limit)?;
        let encoded = identity.encode_bounded(size)?;
        digest.update(&(size as u64).to_be_bytes());
        digest.update(encoded.as_bytes());
        used = used
            .checked_add(size_of::<u64>())
            .and_then(|n| n.checked_add(size))
            .ok_or_else(|| Error::limit("bgp_policy_identity_budget"))?;
    }
    Ok((sha256::hex(&digest.finalize()), used))
}

fn config_identity_json(config: &PolicyConfig) -> Json {
    Json::object([
        ("age_rule", option_text(config.age_rule.map(age_rule_name))),
        (
            "comparison_context",
            Json::string(config.comparison_context.clone()),
        ),
        (
            "criteria_order",
            Json::array(ORDER.into_iter().map(Json::string)),
        ),
        ("med_rule", option_text(config.med_rule.map(med_rule_name))),
        (
            "missing_local_preference",
            config
                .missing_local_preference
                .map_or(Json::Null, Json::from),
        ),
        ("provenance", Json::string(config.provenance.clone())),
        (
            "schema",
            Json::string("pcap-evidence.bgp.best-path-policy.v1"),
        ),
    ])
}

fn candidate_identity_json(candidate: &PolicyCandidate) -> Json {
    let source = &candidate.key.scope.source;
    let scope = Json::object([
        (
            "direction",
            candidate.key.scope.direction.map_or(Json::Null, Json::from),
        ),
        ("generation", Json::from(candidate.key.scope.generation)),
        ("partition_id", Json::string(source.partition_id.clone())),
        (
            "partition_kind",
            Json::string(partition_kind_name(source.kind)),
        ),
        (
            "peer",
            candidate
                .key
                .scope
                .peer
                .as_ref()
                .map_or(Json::Null, |value| Json::string(value.clone())),
        ),
        ("session", Json::string(candidate.key.scope.session.clone())),
        ("source_id", Json::string(source.source_id.clone())),
    ]);
    let path_id = match candidate.key.path_id {
        super::bgp_rib::PathId::Absent => {
            Json::object([("kind", Json::string("absent")), ("value", Json::Null)])
        }
        super::bgp_rib::PathId::Present(value) => Json::object([
            ("kind", Json::string("present")),
            ("value", Json::from(value)),
        ]),
        super::bgp_rib::PathId::Unknown => {
            Json::object([("kind", Json::string("unknown")), ("value", Json::Null)])
        }
    };
    let inputs = &candidate.inputs;
    let age = inputs.age.as_ref().map_or(Json::Null, |age| {
        Json::object([
            ("clock_id", Json::string(age.clock_id.clone())),
            ("observed_order", Json::from(age.observed_order)),
        ])
    });
    let med = inputs.med.map_or(Json::Null, |med| match med {
        MedEvidence::Absent => {
            Json::object([("kind", Json::string("absent")), ("value", Json::Null)])
        }
        MedEvidence::Present(value) => Json::object([
            ("kind", Json::string("present")),
            ("value", Json::from(value)),
        ]),
    });
    let inputs = Json::object([
        ("age", age),
        ("as_path_length", option_u32(inputs.as_path_length)),
        ("ebgp", option_bool(inputs.ebgp)),
        ("igp_metric", option_u32(inputs.igp_metric)),
        ("local_preference", option_u32(inputs.local_preference)),
        ("locally_originated", option_bool(inputs.locally_originated)),
        ("med", med),
        (
            "neighbor_address",
            inputs
                .neighbor_address
                .map_or(Json::Null, |value| Json::string(value.to_string())),
        ),
        ("neighboring_as", option_u32(inputs.neighboring_as)),
        ("origin", inputs.origin.map_or(Json::Null, Json::from)),
        (
            "router_id",
            inputs
                .router_id
                .map_or(Json::Null, |value| Json::string(value.to_string())),
        ),
    ]);
    Json::object([
        (
            "comparison_context",
            Json::string(candidate.comparison_context.clone()),
        ),
        ("family_afi", Json::from(candidate.key.family.afi)),
        ("family_safi", Json::from(candidate.key.family.safi)),
        ("id", Json::string(candidate.id.clone())),
        ("inputs", inputs),
        ("path_id", path_id),
        (
            "prefix",
            Json::object([
                (
                    "address",
                    Json::string(candidate.key.prefix.address.clone()),
                ),
                ("afi", Json::from(candidate.key.prefix.afi)),
                ("length", Json::from(candidate.key.prefix.length)),
                ("safi", Json::from(candidate.key.prefix.safi)),
            ]),
        ),
        (
            "schema",
            Json::string("pcap-evidence.bgp.policy-candidate-identity.v1"),
        ),
        ("scope", scope),
        ("status", Json::string(route_status_name(candidate.status))),
    ])
}

fn option_u32(value: Option<u32>) -> Json {
    value.map_or(Json::Null, Json::from)
}

fn option_bool(value: Option<bool>) -> Json {
    value.map_or(Json::Null, Json::from)
}

fn option_text(value: Option<&'static str>) -> Json {
    value.map_or(Json::Null, Json::string)
}

fn med_rule_name(value: MedRule) -> &'static str {
    match value {
        MedRule::SameNeighborAs => "same_neighbor_as",
        MedRule::CompareAll => "compare_all",
        MedRule::Skip => "skip",
    }
}

fn age_rule_name(value: AgeRule) -> &'static str {
    match value {
        AgeRule::SameClock => "same_clock",
        AgeRule::Skip => "skip",
    }
}

fn partition_kind_name(value: PartitionKind) -> &'static str {
    match value {
        PartitionKind::Captured => "captured",
        PartitionKind::Imported => "imported",
    }
}

fn route_status_name(value: RouteStatus) -> &'static str {
    match value {
        RouteStatus::Active => "active",
        RouteStatus::Stale(StaleKind::Graceful) => "stale_graceful",
        RouteStatus::Stale(StaleKind::LongLivedGraceful) => "stale_long_lived_graceful",
        RouteStatus::StaleAtEor => "stale_at_eor",
        RouteStatus::Withdrawn => "withdrawn",
        RouteStatus::Superseded => "superseded",
        RouteStatus::Unresolved => "unresolved",
        RouteStatus::Rejected => "rejected",
    }
}

fn step_result_name(value: StepResult) -> &'static str {
    match value {
        StepResult::Left => "left",
        StepResult::Right => "right",
        StepResult::Equal => "equal",
        StepResult::Skipped => "skipped",
        StepResult::Unresolved => "unresolved",
    }
}

fn comparison_json(comparison: &Comparison) -> Json {
    let steps = comparison.steps.iter().map(|step| {
        Json::object([
            ("criterion", Json::string(step.criterion)),
            (
                "left",
                step.left
                    .as_ref()
                    .map_or(Json::Null, |value| Json::string(value.clone())),
            ),
            ("reason", Json::string(step.reason)),
            ("result", Json::string(step_result_name(step.result))),
            (
                "right",
                step.right
                    .as_ref()
                    .map_or(Json::Null, |value| Json::string(value.clone())),
            ),
        ])
    });
    Json::object([
        ("left_id", Json::string(comparison.left_id.clone())),
        ("result", Json::string(step_result_name(comparison.result))),
        ("right_id", Json::string(comparison.right_id.clone())),
        ("steps", Json::array(steps)),
    ])
}

fn render_canonical(
    result: &PolicyResult,
    limit: usize,
    mut output: Option<&mut String>,
) -> Result<usize> {
    let mut used = 0usize;
    append_raw(&mut output, &mut used, limit, "{")?;
    let mut first = true;
    write_member(
        &mut output,
        &mut used,
        limit,
        &mut first,
        "candidate_set_fingerprint_sha256",
        Json::string(result.candidate_set_fingerprint_sha256.clone()),
    )?;
    write_member(
        &mut output,
        &mut used,
        limit,
        &mut first,
        "candidate_store_binding",
        Json::string(STORE_BINDING_UNAVAILABLE),
    )?;
    write_member_array(
        &mut output,
        &mut used,
        limit,
        &mut first,
        "comparisons",
        result.comparisons.iter().map(comparison_json),
    )?;
    write_member(
        &mut output,
        &mut used,
        limit,
        &mut first,
        "config_fingerprint_sha256",
        Json::string(result.config_fingerprint_sha256.clone()),
    )?;
    write_member(
        &mut output,
        &mut used,
        limit,
        &mut first,
        "config_provenance",
        Json::string(result.config_provenance.clone()),
    )?;
    write_member(
        &mut output,
        &mut used,
        limit,
        &mut first,
        "endpoint_rib_established",
        Json::from(result.endpoint_rib_established),
    )?;
    write_member_array(
        &mut output,
        &mut used,
        limit,
        &mut first,
        "excluded",
        result.excluded.iter().map(|(id, status)| {
            Json::object([
                ("id", Json::string(id.clone())),
                ("status", Json::string(route_status_name(*status))),
            ])
        }),
    )?;
    write_member(
        &mut output,
        &mut used,
        limit,
        &mut first,
        "identity_scope",
        Json::string("canonical_policy_inputs_only"),
    )?;
    write_member(
        &mut output,
        &mut used,
        limit,
        &mut first,
        "propagated_route_established",
        Json::from(result.propagated_route_established),
    )?;
    write_member(
        &mut output,
        &mut used,
        limit,
        &mut first,
        "schema",
        Json::string(RESULT_SCHEMA),
    )?;
    write_member(
        &mut output,
        &mut used,
        limit,
        &mut first,
        "selected",
        result
            .selected
            .as_ref()
            .map_or(Json::Null, |value| Json::string(value.clone())),
    )?;
    write_member_array(
        &mut output,
        &mut used,
        limit,
        &mut first,
        "unresolved",
        result.unresolved.iter().cloned().map(Json::string),
    )?;
    append_raw(&mut output, &mut used, limit, "}")?;
    Ok(used)
}

fn write_member(
    output: &mut Option<&mut String>,
    used: &mut usize,
    limit: usize,
    first: &mut bool,
    key: &'static str,
    value: Json,
) -> Result<()> {
    write_key(output, used, limit, first, key)?;
    append_raw(output, used, limit, ":")?;
    append_json(output, used, limit, value)
}

fn write_member_array(
    output: &mut Option<&mut String>,
    used: &mut usize,
    limit: usize,
    first: &mut bool,
    key: &'static str,
    values: impl Iterator<Item = Json>,
) -> Result<()> {
    write_key(output, used, limit, first, key)?;
    append_raw(output, used, limit, "[")?;
    for (index, value) in values.enumerate() {
        if index != 0 {
            append_raw(output, used, limit, ",")?;
        }
        append_json(output, used, limit, value)?;
    }
    append_raw(output, used, limit, "]")
}

fn write_key(
    output: &mut Option<&mut String>,
    used: &mut usize,
    limit: usize,
    first: &mut bool,
    key: &'static str,
) -> Result<()> {
    if !*first {
        append_raw(output, used, limit, ",")?;
    }
    *first = false;
    append_json(output, used, limit, Json::string(key))
}

fn append_json(
    output: &mut Option<&mut String>,
    used: &mut usize,
    limit: usize,
    value: Json,
) -> Result<()> {
    let remaining = limit
        .checked_sub(*used)
        .ok_or_else(|| Error::limit("bgp_policy_output_bytes"))?;
    let size = value
        .encoded_len_bounded(remaining)
        .map_err(|_| Error::limit("bgp_policy_output_bytes"))?;
    if let Some(output) = output.as_mut() {
        value
            .append_bounded(output, limit)
            .map_err(|_| Error::limit("bgp_policy_output_bytes"))?;
    }
    *used = used
        .checked_add(size)
        .ok_or_else(|| Error::limit("bgp_policy_output_bytes"))?;
    Ok(())
}

fn append_raw(
    output: &mut Option<&mut String>,
    used: &mut usize,
    limit: usize,
    value: &str,
) -> Result<()> {
    let next = used
        .checked_add(value.len())
        .ok_or_else(|| Error::limit("bgp_policy_output_bytes"))?;
    if next > limit {
        return Err(Error::limit("bgp_policy_output_bytes"));
    }
    if let Some(output) = output.as_mut() {
        output
            .try_reserve(value.len())
            .map_err(|_| Error::limit("bgp_policy_output_allocation"))?;
        output.push_str(value);
    }
    *used = next;
    Ok(())
}

fn check_text(value: &str, limits: &Limits) -> Result<()> {
    if value.trim().is_empty()
        || value.len() > limits.input_bytes.min(1024)
        || value.chars().any(char::is_control)
    {
        return Err(bad(
            "bgp_policy_identity",
            0,
            "nonempty bounded identity required",
        ));
    }
    Ok(())
}
fn compare(left: &PolicyCandidate, right: &PolicyCandidate, config: &PolicyConfig) -> Comparison {
    let a = &left.inputs;
    let b = &right.inputs;
    let mut steps = Vec::with_capacity(ORDER.len());
    let mut decided = StepResult::Equal;
    let values = [
        (
            a.local_preference
                .or(config.missing_local_preference)
                .map(i64::from),
            b.local_preference
                .or(config.missing_local_preference)
                .map(i64::from),
            true,
            "configured_local_preference",
        ),
        (
            a.locally_originated.map(i64::from),
            b.locally_originated.map(i64::from),
            true,
            "explicit_local_origin",
        ),
        (
            a.as_path_length.map(i64::from),
            b.as_path_length.map(i64::from),
            false,
            "as_path_length",
        ),
        (
            a.origin.map(i64::from),
            b.origin.map(i64::from),
            false,
            "origin_type",
        ),
        (
            a.med.map(|value| i64::from(value.value())),
            b.med.map(|value| i64::from(value.value())),
            false,
            "med_scope",
        ),
        (
            a.ebgp.map(i64::from),
            b.ebgp.map(i64::from),
            true,
            "explicit_peer_class",
        ),
        (
            a.igp_metric.map(i64::from),
            b.igp_metric.map(i64::from),
            false,
            "igp_metric",
        ),
        (None, None, false, "same_clock_age"),
    ];
    for (index, (lv, rv, higher, reason)) in values.into_iter().enumerate() {
        let criterion = ORDER[index];
        let mut step = TraceStep {
            criterion,
            left: lv.map(|x| x.to_string()),
            right: rv.map(|x| x.to_string()),
            result: StepResult::Equal,
            reason,
        };
        if index == 7 {
            step.left = a.age.as_ref().map(|x| x.observed_order.to_string());
            step.right = b.age.as_ref().map(|x| x.observed_order.to_string());
        }
        if decided != StepResult::Equal
            || index == 4 && config.med_rule == Some(MedRule::Skip)
            || index == 7 && config.age_rule == Some(AgeRule::Skip)
        {
            step.result = StepResult::Skipped;
        } else if index == 3
            && (a.origin.is_some_and(|value| value > 2) || b.origin.is_some_and(|value| value > 2))
        {
            step.result = StepResult::Unresolved;
            step.reason = "origin_missing_or_invalid";
        } else if index == 4 && config.med_rule.is_none() {
            step.result = StepResult::Unresolved;
            step.reason = "med_policy_configuration_missing";
        } else if index == 4 && config.med_rule == Some(MedRule::SameNeighborAs) {
            if a.neighboring_as.is_none() || b.neighboring_as.is_none() {
                step.result = StepResult::Unresolved;
                step.reason = "neighbor_as_missing";
            } else if a.neighboring_as != b.neighboring_as {
                step.result = StepResult::Skipped;
                step.reason = "different_neighbor_as";
            } else {
                step.result = compare_number(lv, rv, higher);
            }
        } else if index == 7 && config.age_rule.is_none() {
            step.result = StepResult::Unresolved;
            step.reason = "age_policy_configuration_missing";
        } else if index == 7
            && config.age_rule == Some(AgeRule::SameClock)
            && a.age.as_ref().map(|x| &x.clock_id) != b.age.as_ref().map(|x| &x.clock_id)
        {
            step.result = StepResult::Unresolved;
            step.reason = "age_clocks_incomparable";
        } else if index == 7 {
            step.result = match (a.age.as_ref(), b.age.as_ref()) {
                (Some(x), Some(y)) if x.observed_order < y.observed_order => StepResult::Left,
                (Some(x), Some(y)) if x.observed_order > y.observed_order => StepResult::Right,
                (Some(_), Some(_)) => StepResult::Equal,
                _ => StepResult::Unresolved,
            };
        } else {
            step.result = compare_number(lv, rv, higher);
        }
        if matches!(
            step.result,
            StepResult::Left | StepResult::Right | StepResult::Unresolved
        ) {
            decided = step.result;
        }
        steps.push(step);
    }
    for (index, (lv, rv)) in [
        (
            a.router_id.map(|x| u32::from(x) as u128),
            b.router_id.map(|x| u32::from(x) as u128),
        ),
        (
            a.neighbor_address.map(ip_number),
            b.neighbor_address.map(ip_number),
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let mut step = TraceStep {
            criterion: ORDER[index + 8],
            left: lv.map(|x| x.to_string()),
            right: rv.map(|x| x.to_string()),
            result: StepResult::Equal,
            reason: "explicit_tie_break",
        };
        if decided != StepResult::Equal {
            step.result = StepResult::Skipped;
        } else if index == 1
            && a.neighbor_address.map(ip_family) != b.neighbor_address.map(ip_family)
        {
            step.result = StepResult::Unresolved;
            step.reason = "neighbor_address_families_incomparable";
        } else {
            step.result = match (lv, rv) {
                (Some(x), Some(y)) if x < y => StepResult::Left,
                (Some(x), Some(y)) if x > y => StepResult::Right,
                (Some(_), Some(_)) => StepResult::Equal,
                _ => StepResult::Unresolved,
            };
        }
        if matches!(
            step.result,
            StepResult::Left | StepResult::Right | StepResult::Unresolved
        ) {
            decided = step.result;
        }
        steps.push(step);
    }
    Comparison {
        left_id: left.id.clone(),
        right_id: right.id.clone(),
        steps,
        result: decided,
    }
}
fn compare_number(left: Option<i64>, right: Option<i64>, higher: bool) -> StepResult {
    match (left, right) {
        (Some(a), Some(b)) if a == b => StepResult::Equal,
        (Some(a), Some(b)) if (a > b) == higher => StepResult::Left,
        (Some(_), Some(_)) => StepResult::Right,
        _ => StepResult::Unresolved,
    }
}
fn ip_number(address: IpAddr) -> u128 {
    match address {
        IpAddr::V4(v) => u128::from(u32::from(v)),
        IpAddr::V6(v) => u128::from(v),
    }
}
fn ip_family(address: IpAddr) -> u8 {
    match address {
        IpAddr::V4(_) => 4,
        IpAddr::V6(_) => 6,
    }
}
