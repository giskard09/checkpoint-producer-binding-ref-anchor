"""Configured-operator RPC corroboration, not independent identity verification.

Standard-library only so the quorum policy can be tested without RPC access
or the signature verifier's cryptographic dependencies.
"""
import datetime


def _operator_id(value):
    if not isinstance(value, str):
        return None
    # Reject non-ASCII BEFORE any case normalization: casefold() would otherwise
    # merge distinct IDs (e.g. "Straße"/"strasse", KELVIN SIGN/"k") into one operator.
    stripped = value.strip(" \t")
    if not stripped.isascii():
        return None
    normalized = stripped.lower()
    # A reserved diagnostic bucket is not a configured operator identity.
    if normalized == "unknown":
        return None
    allowed = "abcdefghijklmnopqrstuvwxyz0123456789._-"
    return normalized if normalized and all(c in allowed for c in normalized) else None


def _block_hash(value):
    if not isinstance(value, str):
        return None
    value = value.lower()
    if len(value) == 66 and value.startswith("0x") and all(c in "0123456789abcdef" for c in value[2:]):
        return value
    return None


def _alias(label, index):
    # Configured labels should be stable, non-secret aliases, not RPC URLs.
    # Also avoid forwarding accidental URL/userinfo/query credentials.
    if isinstance(label, str) and label.strip() and not any(c in label for c in "/?#@:"):
        return label.strip()
    return f"endpoint-{index + 1}"


def recheck_inclusion_multi_rpc(block_number, recorded_block_hash, recorded_chain_id,
                                 endpoints, min_endpoints=2):
    """Recheck a recorded chain point using explicitly configured operators.

    endpoints: (alias, operator_id, query_fn) triples. query_fn(block_number)
    returns {"chain_id": int, "block_hash": "0x..."} or raises on failure.
    Legacy (alias, query_fn) pairs are accepted as unknown-operator entries:
    they contribute ZERO to the strict quorum, not one shared "unknown" vote.

    min_endpoints retains its API name but now counts distinct normalized
    operator IDs, never URLs or labels. An ID is trimmed (ASCII space/tab
    only); non-ASCII input is rejected before any case normalization; the rest
    is lowercased and must consist only of ASCII letters, digits, dot,
    underscore and hyphen (no length or start/end-character rule). Missing or
    invalid IDs and the reserved ID "unknown" do not qualify. The
    configuration's identity mapping is assumed, not authenticated.

    All reachable, correct-chain, well-formed hash observations must agree,
    including multiple URLs for one operator and entries with unknown identity.
    Check disagreement BEFORE operator deduplication: never keep just the first
    answer from an operator. Unreachable/wrong-chain/malformed observations are
    excluded, as in the original verifier. No majority voting, finality claim,
    light-client verification or protection against mislabeling/collusion.

    Audit output contains safe aliases, normalized IDs, and exclusion reason
    codes, never query functions, raw RPC exception text, or URL credentials.
    """
    endpoints = list(endpoints)
    reports = []
    result = {
        "status": "unknown",
        "checked_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "chain_id": recorded_chain_id, "block": block_number,
        "endpoints_queried": 0, "endpoints_qualifying": 0,
        "operators_qualifying": 0, "operator_ids_qualifying": [],
        "quorum_operator_ids": [], "reports": reports,
        "assurance": "configured-operator-corroboration",
    }

    def unknown(code, reason):
        return {**result, "reason_code": code, "reason": reason}

    if type(min_endpoints) is not int or min_endpoints < 1:
        return unknown("invalid_min_endpoints", "min_endpoints must be a positive integer operator threshold")
    recorded_hash = _block_hash(recorded_block_hash)
    if (recorded_hash is None or type(recorded_chain_id) is not int or recorded_chain_id < 1
            or type(block_number) is not int or block_number < 0):
        return unknown("invalid_chain_point", "A nonnegative height, positive chain ID and 32-byte block hash are required")

    for index, entry in enumerate(endpoints):
        report = {
            "label": f"endpoint-{index + 1}", "operator_id": None,
            "chain_view_qualifies": False, "counts_toward_quorum": False,
            "exclusion_reason": None,
        }
        reports.append(report)
        if not isinstance(entry, (tuple, list)) or len(entry) not in (2, 3):
            report["exclusion_reason"] = "invalid_endpoint_config"
            continue
        label, operator, query_fn = (entry[0], None, entry[1]) if len(entry) == 2 else entry
        report["label"] = _alias(label, index)
        report["operator_id"] = _operator_id(operator)
        if not callable(query_fn):
            report["exclusion_reason"] = "invalid_endpoint_config"
            continue
        result["endpoints_queried"] += 1
        try:
            observation = query_fn(block_number)
        except Exception:
            # RPC exceptions commonly embed credential-bearing request URLs.
            report["exclusion_reason"] = "query_error"
            continue
        if not isinstance(observation, dict):
            report["exclusion_reason"] = "malformed_response"
            continue
        chain_id = observation.get("chain_id")
        if type(chain_id) is not int or chain_id != recorded_chain_id:
            report["exclusion_reason"] = "wrong_chain_id"
            continue
        observed_hash = _block_hash(observation.get("block_hash"))
        if observed_hash is None:
            report["exclusion_reason"] = "invalid_block_hash"
            continue
        report["chain_view_qualifies"] = True
        report["block_hash"] = observed_hash
        report["counts_toward_quorum"] = report["operator_id"] is not None
        if report["operator_id"] is None:
            # Distinguish: no operator ID supplied (missing) vs. supplied but rejected (invalid).
            if operator is None or (isinstance(operator, str) and not operator.strip(" \t")):
                report["exclusion_reason"] = "operator_id_missing"
            else:
                report["exclusion_reason"] = "operator_id_invalid"

    qualifying = [r for r in reports if r["chain_view_qualifies"]]
    operator_ids = sorted({r["operator_id"] for r in qualifying if r["counts_toward_quorum"]})
    result["endpoints_qualifying"] = len(qualifying)
    result["operators_qualifying"] = len(operator_ids)
    result["operator_ids_qualifying"] = operator_ids
    distinct_hashes = {r["block_hash"] for r in qualifying}
    if len(distinct_hashes) > 1:
        return unknown("block_hash_disagreement", "Qualifying endpoints disagree on the block hash at this height")
    if len(operator_ids) < min_endpoints:
        return unknown("insufficient_operators",
                       f"only {len(operator_ids)} explicitly identified qualifying operators; need >= {min_endpoints}")
    agreed_hash = next(iter(distinct_hashes))
    return {**result, "status": "included" if agreed_hash == recorded_hash else "reorged",
            "block_hash": agreed_hash, "quorum_operator_ids": operator_ids}
