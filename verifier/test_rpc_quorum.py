"""Deterministic synthetic coverage only: no network calls or onchain writes."""
import json
import unittest
from unittest.mock import Mock

from rpc_quorum import recheck_inclusion_multi_rpc

CHAIN = 8453
HEIGHT = 123
HASH = "0x" + "11" * 32
OTHER = "0x" + "22" * 32


def endpoint(label, operator, block_hash=HASH, chain_id=CHAIN):
    return (label, operator, lambda _: {"chain_id": chain_id, "block_hash": block_hash})


def check(entries, minimum=2):
    return recheck_inclusion_multi_rpc(HEIGHT, HASH, CHAIN, entries, min_endpoints=minimum)


class OperatorQuorumTests(unittest.TestCase):
    def test_distinct_operators_agree(self):
        result = check([endpoint("a", "provider-a"), endpoint("b", "provider-b")])
        self.assertEqual(result["status"], "included")
        self.assertEqual(result["quorum_operator_ids"], ["provider-a", "provider-b"])
        self.assertEqual(result["operators_qualifying"], 2)
        self.assertEqual(result["endpoints_qualifying"], 2)
        self.assertEqual(result["endpoints_queried"], 2)
        self.assertEqual(result["assurance"], "configured-operator-corroboration")
        self.assertTrue(result["checked_at"])

    def test_aliases_of_one_operator_do_not_make_quorum(self):
        result = check([endpoint("a", "provider-a"), endpoint("b", "provider-a")])
        self.assertEqual(result["status"], "unknown")
        self.assertEqual(result["reason_code"], "insufficient_operators")
        self.assertEqual(result["operators_qualifying"], 1)
        self.assertEqual(result["endpoints_qualifying"], 2)
        self.assertEqual(result["quorum_operator_ids"], [])

    def test_unknown_pair_plus_one_named_operator_is_insufficient(self):
        result = check([endpoint("a", None), endpoint("b", ""), endpoint("c", "provider-c")])
        self.assertEqual(result["status"], "unknown")
        self.assertEqual(result["operators_qualifying"], 1)
        self.assertEqual(result["endpoints_qualifying"], 3)
        self.assertEqual([r["exclusion_reason"] for r in result["reports"]],
                         ["operator_id_missing", "operator_id_missing", None])

    def test_only_unknown_operators_never_make_quorum(self):
        for minimum in (1, 2):
            with self.subTest(minimum=minimum):
                result = check([endpoint("a", None), endpoint("b", "  ")], minimum)
                self.assertEqual(result["status"], "unknown")
                self.assertEqual(result["operators_qualifying"], 0)

    def test_reserved_unknown_id_never_counts_after_normalization(self):
        for reserved in ("unknown", " UNKNOWN ", "UnKnOwN"):
            with self.subTest(operator=reserved):
                result = check([endpoint("unknown", reserved), endpoint("a", "provider-a")])
                self.assertEqual(result["status"], "unknown")
                self.assertEqual(result["reason_code"], "insufficient_operators")
                self.assertEqual(result["operators_qualifying"], 1)
                self.assertEqual(result["operator_ids_qualifying"], ["provider-a"])
                self.assertEqual(result["quorum_operator_ids"], [])
                self.assertIsNone(result["reports"][0]["operator_id"])
                self.assertFalse(result["reports"][0]["counts_toward_quorum"])
                self.assertEqual(result["reports"][0]["exclusion_reason"], "operator_id_invalid")
                self.assertEqual(check([endpoint("unknown", reserved)], 1)["status"], "unknown")

    def test_reserved_unknown_agrees_but_only_named_operators_make_quorum(self):
        result = check([endpoint("a", "provider-a"), endpoint("b", "provider-b"),
                        endpoint("unknown", "unknown")])
        self.assertEqual(result["status"], "included")
        self.assertEqual(result["endpoints_qualifying"], 3)
        self.assertEqual(result["operators_qualifying"], 2)
        self.assertEqual(result["operator_ids_qualifying"], ["provider-a", "provider-b"])
        self.assertEqual(result["quorum_operator_ids"], ["provider-a", "provider-b"])
        self.assertEqual(result["reports"][2]["exclusion_reason"], "operator_id_invalid")

    def test_reserved_unknown_conflicting_view_blocks_two_named_operators(self):
        result = check([endpoint("a", "provider-a"), endpoint("b", "provider-b"),
                        endpoint("unknown", " UNKNOWN ", OTHER)])
        self.assertEqual(result["status"], "unknown")
        self.assertEqual(result["reason_code"], "block_hash_disagreement")
        self.assertEqual(result["operators_qualifying"], 2)
        self.assertEqual(result["quorum_operator_ids"], [])

    def test_reserved_word_does_not_exclude_distinct_longer_ids(self):
        result = check([endpoint("a", "unknown-provider"), endpoint("b", "provider-b")])
        self.assertEqual(result["status"], "included")
        self.assertEqual(result["quorum_operator_ids"], ["provider-b", "unknown-provider"])

    def test_legacy_pairs_remain_callable_but_supply_no_operator_vote(self):
        entries = [("a", endpoint("a", None)[2]), ("b", endpoint("b", None)[2])]
        self.assertEqual(check(entries)["status"], "unknown")
        self.assertEqual(check(entries)["operators_qualifying"], 0)

    def test_operator_case_and_whitespace_are_normalized(self):
        result = check([endpoint("a", " Provider-A "), endpoint("b", "provider-a")])
        self.assertEqual(result["status"], "unknown")
        self.assertEqual(result["operator_ids_qualifying"], ["provider-a"])
        self.assertEqual([r["operator_id"] for r in result["reports"]], ["provider-a"] * 2)

    def test_matching_client_versions_and_hashes_do_not_merge_operator_ids(self):
        def query(_):
            return {"chain_id": CHAIN, "block_hash": HASH, "client_version": "same-client"}
        result = check([("a", "provider-a", query), ("b", "provider-b", query)])
        self.assertEqual(result["status"], "included")
        self.assertEqual(result["operators_qualifying"], 2)

    def test_duplicate_url_does_not_increase_operator_count(self):
        result = check([endpoint("same", "a"), endpoint("same", "a"), endpoint("other", "b")])
        self.assertEqual(result["status"], "included")
        self.assertEqual(result["operators_qualifying"], 2)
        self.assertEqual(check([endpoint("same", "a"), endpoint("same", "a"), endpoint("other", "b")], 3)["status"], "unknown")

    def test_same_operator_conflict_is_not_hidden_by_deduplication(self):
        entries = [endpoint("a1", "a"), endpoint("a2", "a", OTHER), endpoint("b", "b")]
        for ordered in (entries, list(reversed(entries))):
            result = check(ordered)
            self.assertEqual(result["status"], "unknown")
            self.assertEqual(result["reason_code"], "block_hash_disagreement")
            self.assertNotIn("block_hash", result)

    def test_distinct_operator_disagreement_stays_unknown(self):
        result = check([endpoint("a", "a"), endpoint("b", "b", OTHER)])
        self.assertEqual(result["reason_code"], "block_hash_disagreement")
        self.assertEqual(result["quorum_operator_ids"], [])

    def test_unknown_operator_conflict_still_blocks_verdict(self):
        result = check([endpoint("a", "a"), endpoint("b", "b"), endpoint("unknown", None, OTHER)])
        self.assertEqual(result["reason_code"], "block_hash_disagreement")

    def test_agreed_different_hash_is_reorged_not_finalized(self):
        result = check([endpoint("a", "a", OTHER), endpoint("b", "b", OTHER)])
        self.assertEqual(result["status"], "reorged")
        self.assertEqual(result["block_hash"], OTHER)
        self.assertNotIn("finalized", result)

    def test_hash_case_is_normalized_without_merging_operators(self):
        upper = "0x" + "AB" * 32
        result = recheck_inclusion_multi_rpc(HEIGHT, upper.lower(), CHAIN,
                                            [endpoint("a", "a", upper), endpoint("b", "b", upper.lower())])
        self.assertEqual(result["status"], "included")
        self.assertEqual(result["operators_qualifying"], 2)

    def test_wrong_chain_and_rpc_errors_never_vote(self):
        secret = "https://user:secret@rpc.invalid/api-key?token=secret"
        failure = Mock(side_effect=TimeoutError(secret))
        result = check([endpoint("a", "a"), endpoint("wrong", "b", chain_id=1),
                        (secret, "c", failure)])
        self.assertEqual(result["status"], "unknown")
        self.assertEqual(result["operators_qualifying"], 1)
        self.assertEqual([r["exclusion_reason"] for r in result["reports"]], [None, "wrong_chain_id", "query_error"])
        self.assertEqual(result["reports"][2]["label"], "endpoint-3")
        self.assertNotIn("secret", json.dumps(result))

    def test_malformed_responses_are_excluded(self):
        for response in (None, [], "bad", {"chain_id": CHAIN, "block_hash": 1},
                         {"chain_id": CHAIN, "block_hash": "0x123"}, {"chain_id": True, "block_hash": HASH}):
            with self.subTest(response=response):
                result = check([endpoint("a", "a"), ("b", "b", lambda _, r=response: r)])
                self.assertEqual(result["status"], "unknown")
                self.assertEqual(result["operators_qualifying"], 1)

    def test_invalid_operator_ids_are_unknown_and_not_echoed(self):
        for operator in (42, [], {}, "https://secret.invalid?key=secret", "  "):
            with self.subTest(operator=operator):
                result = check([endpoint("a", "a"), endpoint("b", operator)])
                self.assertEqual(result["status"], "unknown")
                self.assertIsNone(result["reports"][1]["operator_id"])
                self.assertNotIn("secret", json.dumps(result))

    def test_invalid_thresholds_fail_closed_before_querying(self):
        query = Mock()
        for minimum in (0, -1, True, 1.5, "2"):
            with self.subTest(minimum=minimum):
                result = check([("a", "a", query)], minimum)
                self.assertEqual(result["reason_code"], "invalid_min_endpoints")
        query.assert_not_called()

    def test_invalid_recorded_chain_points_fail_closed(self):
        query = Mock()
        for height, block_hash, chain in ((-1, HASH, CHAIN), (HEIGHT, "bad", CHAIN),
                                         (HEIGHT, HASH, True), (HEIGHT, HASH, 0)):
            result = recheck_inclusion_multi_rpc(height, block_hash, chain, [("a", "a", query)])
            self.assertEqual(result["reason_code"], "invalid_chain_point")
        query.assert_not_called()

    def test_empty_or_malformed_endpoint_config_is_safe(self):
        self.assertEqual(check([])["status"], "unknown")
        for entry in (None, {}, ("a",), ("a", "b", None), ("a", "b", None, None)):
            with self.subTest(entry=entry):
                result = check([endpoint("good", "a"), entry])
                self.assertEqual(result["status"], "unknown")
                self.assertEqual(result["reports"][1]["exclusion_reason"], "invalid_endpoint_config")


class OperatorIdNormalizationTests(unittest.TestCase):
    def test_non_ascii_id_contributes_zero_votes(self):
        # Old casefold() turned these into valid IDs "strasse" / "k" and counted a vote.
        for bad in ["Stra\u00dfe", "\u212a"]:
            result = check([endpoint("a", bad)], minimum=1)
            self.assertEqual(result["operators_qualifying"], 0, bad)
            self.assertEqual(result["reason_code"], "insufficient_operators", bad)

    def test_non_ascii_id_cannot_pair_with_ascii_lookalike_to_reach_quorum(self):
        for bad, good in [("Stra\u00dfe", "strasse"), ("\u212a", "k")]:
            result = check([endpoint("a", bad), endpoint("b", good)], minimum=2)
            self.assertEqual(result["operators_qualifying"], 1, bad)
            self.assertEqual(result["quorum_operator_ids"], [])

    def test_punctuation_variants_stay_distinct(self):
        result = check([endpoint("a", "provider.a"), endpoint("b", "provider-a")])
        self.assertEqual(result["status"], "included")
        self.assertEqual(result["operators_qualifying"], 2)

    def test_reserved_unknown_still_disagrees_but_does_not_vote(self):
        result = check([endpoint("a", "provider-a"), endpoint("b", "provider-b"),
                        endpoint("c", "UNKNOWN", block_hash=OTHER)])
        self.assertEqual(result["status"], "unknown")


def _config_boundary(raw):
    """Test-side illustration of a config-reader boundary (not shipped API).

    A reader that accepts a line terminator removes EXACTLY ONE trailing
    terminator (CRLF, LF or CR) at the parse edge, then hands the result to
    the strict canonicalizer unchanged. The strict _operator_id never widens.
    """
    for terminator in ("\r\n", "\n", "\r"):
        if raw.endswith(terminator):
            return raw[:-len(terminator)]
    return raw


class OperatorIdLineTerminatorTests(unittest.TestCase):
    """LF / CRLF / embedded-newline fixtures against the strict _operator_id.

    Policy pinned here: only ASCII space and tab are trimmed. Any other
    whitespace/control character (including line terminators) makes the ID
    invalid: zero votes, operator_id None, stable exclusion reason
    "operator_id_invalid", and the raw value is never echoed.
    """

    INVALID = {
        "trailing_lf": "provider-a\n",
        "trailing_crlf": "provider-a\r\n",
        "trailing_cr": "provider-a\r",
        "leading_lf": "\nprovider-a",
        "embedded_lf": "provider\na",
        "embedded_crlf": "provider\r\na",
        "double_trailing_lf": "provider-a\n\n",
        "vertical_tab": "provider-a\x0b",
        "form_feed": "provider-a\x0c",
        "nul": "provider-a\x00",
        "next_line_u0085": "provider-a\u0085",
        "line_separator_u2028": "provider-a\u2028",
        "lf_only": "\n",
    }

    def test_line_terminator_ids_are_rejected_with_zero_votes(self):
        for name, bad in self.INVALID.items():
            with self.subTest(case=name):
                result = check([endpoint("a", bad), endpoint("b", "provider-b")])
                self.assertIsNone(result["reports"][0]["operator_id"])
                self.assertFalse(result["reports"][0]["counts_toward_quorum"])
                self.assertEqual(result["reports"][0]["exclusion_reason"], "operator_id_invalid")
                self.assertEqual(result["operators_qualifying"], 1)
                self.assertEqual(result["status"], "unknown")
                self.assertEqual(result["reason_code"], "insufficient_operators")
                self.assertEqual(result["quorum_operator_ids"], [])

    def test_line_terminator_id_cannot_pair_with_its_clean_twin(self):
        for name, bad in self.INVALID.items():
            if name in ("lf_only", "embedded_lf", "embedded_crlf"):
                continue
            with self.subTest(case=name):
                result = check([endpoint("a", bad), endpoint("b", "provider-a")])
                self.assertEqual(result["operators_qualifying"], 1)
                self.assertEqual(result["status"], "unknown")

    def test_line_terminator_ids_are_not_echoed_in_output(self):
        for bad in ("https://secret.invalid/x?k=secret\n", "secret\r\nvalue"):
            result = check([endpoint("a", "a"), endpoint("b", bad)])
            self.assertIsNone(result["reports"][1]["operator_id"])
            self.assertNotIn("secret", json.dumps(result))

    def test_exclusion_reason_stays_chain_reason_when_endpoint_also_fails(self):
        result = check([endpoint("a", "a"), endpoint("b", "provider-b\n", chain_id=1)])
        self.assertEqual(result["reports"][1]["exclusion_reason"], "wrong_chain_id")
        self.assertIsNone(result["reports"][1]["operator_id"])
        self.assertEqual(result["operators_qualifying"], 1)

    def test_boundary_strips_exactly_one_terminator_then_strict_applies(self):
        ok = [("provider-a\n", "provider-a"), ("provider-a\r\n", "provider-a"),
              ("provider-a\r", "provider-a"), (" Provider-A\t\n", "provider-a")]
        for raw, expected in ok:
            with self.subTest(raw=raw):
                result = check([endpoint("a", _config_boundary(raw)), endpoint("b", "provider-b")])
                self.assertEqual(result["status"], "included")
                self.assertEqual(result["quorum_operator_ids"], sorted([expected, "provider-b"]))
        for raw in ("provider-a\n\n", "provider-a\r\n\r\n", "provider\na\n", "provider-a\x0b\n"):
            with self.subTest(raw=raw):
                result = check([endpoint("a", _config_boundary(raw)), endpoint("b", "provider-b")])
                self.assertEqual(result["operators_qualifying"], 1)
                self.assertEqual(result["status"], "unknown")


class OperatorIdPositiveAndNonAsciiFixtures(unittest.TestCase):
    def test_dot_and_hyphen_variants_are_two_operators(self):
        # Run 2026-11-10: provider.a + provider-a => 2 distinct operators.
        result = check([endpoint("a", "provider.a"), endpoint("b", "provider-a")])
        self.assertEqual(result["status"], "included")
        self.assertEqual(result["operators_qualifying"], 2)
        self.assertEqual(result["quorum_operator_ids"], ["provider-a", "provider.a"])

    def test_space_tab_trim_and_case_fold_are_one_operator(self):
        result = check([endpoint("a", " Provider-A\t"), endpoint("b", "provider-a")])
        self.assertEqual(result["operators_qualifying"], 1)
        self.assertEqual(result["reason_code"], "insufficient_operators")

    def test_non_ascii_ids_get_zero_votes_and_stable_reason(self):
        bad_ids = ["Stra\u00dfe", "\u212a", "provider-\u00e1", "\uff50rovider-a",
                   "provider-a\u00a0", "\u0131", "provider-a\u200b"]
        for bad in bad_ids:
            with self.subTest(operator=bad):
                result = check([endpoint("a", bad), endpoint("b", "provider-b")])
                self.assertIsNone(result["reports"][0]["operator_id"])
                self.assertEqual(result["reports"][0]["exclusion_reason"], "operator_id_invalid")
                self.assertEqual(result["operators_qualifying"], 1)
                self.assertEqual(result["status"], "unknown")

    def test_url_label_gets_safe_alias_and_no_raw_url_in_output(self):
        url = "https://user:secret@rpc.invalid/path?key=secret"
        result = check([(url, "provider-a", lambda _: {"chain_id": CHAIN, "block_hash": HASH}),
                        endpoint("b", "provider-b\n")])
        self.assertEqual(result["reports"][0]["label"], "endpoint-1")
        self.assertEqual(result["reports"][0]["operator_id"], "provider-a")
        self.assertNotIn("secret", json.dumps(result))
        self.assertNotIn("rpc.invalid", json.dumps(result))


if __name__ == "__main__":
    unittest.main()
