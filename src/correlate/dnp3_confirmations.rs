//! Fragment-level candidate identifiers, deliberately separate from transactions.
use crate::engine::{ApplicationAnalysis, ApplicationData};
use crate::semantics::dnp3_workflow::{verified_fragment_witness, FragmentWitness};
use crate::{Error, ErrorCode, Limits, Result};
use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct FragmentRef {
    pub application: usize,
    pub fragment: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Dnp3ConfirmationFragment {
    pub reference: FragmentRef,
    /// Caller-established capture direction (0 or 1), not an inferred DNP3 role.
    pub direction: usize,
    pub witness: FragmentWitness,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Dnp3ExcludedConfirmationTarget {
    pub fragment: Dnp3ConfirmationFragment,
    pub reason: &'static str,
}

/// One identifier group. Multiple confirms/targets are alternatives, NOT edges
/// choosing one partner. Unclassified rows contain references but no trusted
/// witness values; original fragment/link evidence remains in the analysis.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Dnp3ConfirmationCandidate {
    pub flow: usize,
    pub confirms: Vec<Dnp3ConfirmationFragment>,
    pub targets: Vec<Dnp3ConfirmationFragment>,
    pub excluded_targets: Vec<Dnp3ExcludedConfirmationTarget>,
    pub unclassified_fragments: Vec<FragmentRef>,
    pub status: &'static str,
    pub reason: &'static str,
    pub error: Option<Error>,
}

#[derive(Default)]
struct Group {
    confirms: Vec<Dnp3ConfirmationFragment>,
    responses: Vec<Dnp3ConfirmationFragment>,
}
// Capture, flow, confirmer's individual source/destination, sequence, UNS.
type Key = ([u8; 32], usize, u16, u16, u8, bool);

fn charge(work: &mut usize, amount: usize, limits: &Limits) -> Result<()> {
    *work = work
        .checked_add(amount)
        .filter(|n| *n <= limits.max_correlation_checks)
        .ok_or_else(|| Error::limit("dnp3_confirmation_correlation_work"))?;
    Ok(())
}

/// Bounded, non-secure confirmation candidates within caller-established flows.
/// Verifies fragments independently of complete-message membership. A target
/// must request confirmation and match reversed individual addresses, opposite
/// capture directions AND link DIRs, fragment sequence and UNS namespace.
///
/// No timestamp, ordering, port, FCB/FCV or endpoint-state heuristic selects a
/// partner. Identifier reuse anywhere in this query remains ambiguous. Invalid
/// or unsupported fragments conservatively block positive candidates in their
/// flow because their true identifier cannot safely be assigned a bucket.
/// Work/retention/output growth is bounded by existing correlation/message limits;
/// exhaustion returns Err, never a silently truncated or partially successful list.
pub fn dnp3_confirmation_candidates(
    applications: &[ApplicationAnalysis],
    limits: &Limits,
) -> Result<Vec<Dnp3ConfirmationCandidate>> {
    let mut groups: BTreeMap<Key, Group> = BTreeMap::new();
    let mut invalid: BTreeMap<usize, Vec<FragmentRef>> = BTreeMap::new();
    let mut output = Vec::new();
    let mut work = 0usize;
    let mut fragments = 0usize;
    for (ai, application) in applications.iter().enumerate() {
        charge(&mut work, 1, limits)?;
        let ApplicationData::Dnp3(result) = &application.data else {
            continue;
        };
        for (fi, fragment) in result.fragments.iter().enumerate() {
            charge(&mut work, 1, limits)?;
            fragments = fragments
                .checked_add(1)
                .filter(|n| *n <= limits.max_protocol_messages)
                .ok_or_else(|| Error::limit("dnp3_confirmation_fragments"))?;
            // Verify before filtering by role: otherwise forged APDU/function
            // metadata could hide a duplicate CONFIRM whose original link bytes
            // still encode function 0. Unsupported contexts fail closed as well.
            let reference = FragmentRef {
                application: ai,
                fragment: fi,
            };
            let verified = if application.direction <= 1 && application.protocol == "dnp3" {
                verified_fragment_witness(result, fragment, limits, &mut work)
            } else {
                Err(Error::new(
                    ErrorCode::Invariant,
                    0,
                    "dnp3_confirmation_application_scope_invalid",
                    "protocol or captured direction disagrees with the supplied DNP3 scope",
                ))
            };
            let witness = match verified {
                Ok(witness) => witness,
                Err(error) if error.code == ErrorCode::LimitExceeded => return Err(error),
                Err(error) => {
                    invalid.entry(application.flow).or_default().push(reference);
                    output.push(Dnp3ConfirmationCandidate {
                        flow: application.flow,
                        confirms: Vec::new(),
                        targets: Vec::new(),
                        excluded_targets: Vec::new(),
                        unclassified_fragments: vec![reference],
                        status: "unclassified",
                        reason: error.field,
                        error: Some(error),
                    });
                    continue;
                }
            };
            if !matches!(witness.header.function, 0 | 0x81 | 0x82) {
                continue;
            }
            let confirm = witness.header.function == 0;
            let (source, destination) = if confirm {
                (witness.source, witness.destination)
            } else {
                (witness.destination, witness.source)
            };
            let key = (
                witness.packets[0].capture, // verifier established nonempty, same-capture witnesses
                application.flow,
                source,
                destination,
                witness.header.sequence(),
                witness.header.unsolicited(),
            );
            let group = groups.entry(key).or_default();
            let observed = Dnp3ConfirmationFragment {
                reference,
                direction: application.direction,
                witness,
            };
            if confirm {
                group.confirms.push(observed);
            } else {
                group.responses.push(observed);
            }
        }
    }
    for ((_, flow, _, _, _, _), group) in groups {
        if group.confirms.is_empty() {
            continue;
        }
        charge(&mut work, group.confirms.len(), limits)?;
        let mut targets = Vec::new();
        let mut excluded_targets = Vec::new();
        for response in group.responses {
            charge(&mut work, 1, limits)?;
            let mut opposite_capture = false;
            let mut opposite_link = false;
            let mut jointly_opposite = false;
            for confirm in &group.confirms {
                charge(&mut work, 1, limits)?;
                let capture = confirm.direction != response.direction;
                let link = confirm.witness.link_direction != response.witness.link_direction;
                opposite_capture |= capture;
                opposite_link |= link;
                jointly_opposite |= capture && link;
            }
            let reason = if !response.witness.header.confirm_requested() {
                Some("target_does_not_request_confirmation")
            } else if !opposite_capture {
                Some("captured_application_directions_not_opposite")
            } else if !opposite_link {
                Some("link_dir_not_opposite")
            } else if !jointly_opposite {
                Some("direction_evidence_not_jointly_compatible")
            } else {
                None
            };
            if let Some(reason) = reason {
                excluded_targets.push(Dnp3ExcludedConfirmationTarget {
                    fragment: response,
                    reason,
                });
            } else {
                targets.push(response);
            }
        }
        let unclassified_fragments = if let Some(refs) = invalid.get(&flow) {
            charge(&mut work, refs.len(), limits)?;
            refs.clone()
        } else {
            Vec::new()
        };
        let (status, reason) = if !unclassified_fragments.is_empty() {
            ("ambiguous", "unverified_fragment_identifier_in_same_flow")
        } else if group.confirms.len() > 1 {
            ("ambiguous", "duplicate_or_reused_confirmation_identifier")
        } else if targets.is_empty() {
            (
                "unmatched_confirmation",
                "no_verified_response_fragment_matches_all_confirmation_fields",
            )
        } else if targets.len() > 1 || !excluded_targets.is_empty() {
            ("ambiguous", "duplicate_or_reused_response_identifier")
        } else {
            (
                "candidate_confirmation",
                "unique_verified_fragment_identifiers_not_receipt_or_causality",
            )
        };
        output.push(Dnp3ConfirmationCandidate {
            flow,
            confirms: group.confirms,
            targets,
            excluded_targets,
            unclassified_fragments,
            status,
            reason,
            error: None,
        });
    }
    Ok(output)
}
