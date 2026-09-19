"""Versioned coverage-aware comparison, preserving v1 bundle verification.

A missing earlier field/observation in the SAME layer also blocks a stronger
first-divergence claim. Raw alternatives and parser statuses remain independent.
"""
from .contract import compare_fields_v1, InvalidResearch, LAYERS, MAX_ROWS

SCHEMA = "pcap-evidence.research-differential.v2"

def compare(left, right, *, maximum=10000):
    if type(maximum) is not int or not 1 <= maximum <= MAX_ROWS:
        raise InvalidResearch("comparison row budget must be an integer")
    result = compare_fields_v1(left, right, maximum=maximum)
    result["schema"] = SCHEMA
    result["comparison_policy"] = "layer-source-anchor-field-order/2"
    result["producer_authentication"] = "not_established_by_comparison"
    first = result.get("first_semantic_divergence")
    if first is not None:
        layer = first["layer"]
        earlier = [r for r in result["rows"][:first["row"]]
                   if r["result"] == "not_comparable"]
        current_complete = left["coverage"][layer] == right["coverage"][layer] == "complete"
        first["earlier_unresolved_observations"] = [
            {k: r[k] for k in ("layer", "key", "field", "reason")} for r in earlier
        ]
        first["current_layer_coverage_complete"] = current_complete
        first["earliest_within_declared_coverage"] = (
            not first["earlier_unresolved_layers"] and not earlier and current_complete
        )
        first["claim"] = ("first_difference_within_complete_declared_prefix"
                          if first["earliest_within_declared_coverage"]
                          else "first_observed_difference_with_coverage_gaps")
        first["raw_witness_validation"] = "requires_source_bound_bundle_or_replay"
    return result
