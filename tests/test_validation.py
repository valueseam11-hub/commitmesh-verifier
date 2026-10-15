import json
import unittest

from helpers import *  # noqa: F401,F403
from commitmesh import schema as s
from commitmesh.claim import parse_claim
from commitmesh.evidence import parse_evidence, parse_evidence_item
from commitmesh.manifest import parse_manifest
from commitmesh.policy import parse_policy


class Validation(unittest.TestCase):
    def test_valid_inputs_pass(self):
        parse_manifest(MANIFEST); parse_claim(claim()); parse_policy(POLICY); parse_evidence(good_evidence())

    def test_duplicate_keys_rejected(self):
        with self.assertRaises(s.ValidationError):
            s.loads_strict('{"a":1,"a":2}')

    def test_nan_rejected(self):
        with self.assertRaises(s.ValidationError):
            s.loads_strict('{"a":NaN}')

    def test_deep_nesting_rejected(self):
        with self.assertRaises(s.ValidationError):
            s.loads_strict("[" * 100000 + "]" * 100000)

    def test_oversize_rejected(self):
        with self.assertRaises(s.ValidationError):
            s.loads_strict(b" " * (s.MAX_JSON_BYTES + 1))

    def test_unknown_fields_rejected(self):
        with self.assertRaises(s.ValidationError):
            parse_claim(dict(claim(), admin=True))
        e = good_evidence()[1]
        with self.assertRaises(s.ValidationError):
            parse_evidence_item(dict(e, extra="x"))

    def test_bad_ids_rejected(self):
        for bad in ("", "../x", "a b", "x" * 200, "a\x00b"):
            with self.assertRaises(s.ValidationError):
                parse_claim(claim(claim_id=bad))

    def test_path_traversal_in_changed_paths_rejected(self):
        e = good_evidence()[0]
        for bad in ("/etc/passwd", "../x", "a/../b", "a\\b"):
            with self.assertRaises(s.ValidationError):
                parse_evidence_item(dict(e, changed_paths=[bad]))

    def test_unknown_component_cannot_carry_digest(self):
        m = clone(MANIFEST); m["components"]["model"]["digest"] = D
        with self.assertRaises(s.ValidationError):
            parse_manifest(m)

    def test_bool_is_not_an_integer(self):
        with self.assertRaises(s.ValidationError):
            parse_policy(dict(POLICY, version=True))

    def test_prohibited_path_pattern_is_case_sensitive(self):
        ev = good_evidence(); ev[0]["changed_paths"] = [".GITHUB/workflows/x.yml"]
        # documented: matching is case-sensitive; use explicit patterns for case-insensitive filesystems
        self.assertEqual(run(ev)["outcome_mark"], "verified")


if __name__ == "__main__":
    unittest.main()
