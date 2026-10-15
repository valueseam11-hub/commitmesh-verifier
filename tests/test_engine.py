import unittest

from helpers import *  # noqa: F401,F403
from commitmesh.manifest import stateprint


class ThreeCaseBenchmark(unittest.TestCase):
    def test_1_supported_fix_is_verified(self):
        self.assertEqual(run()["outcome_mark"], "verified")

    def test_2_missing_deployment_is_inconclusive(self):
        r = run(drop("deployment"))
        self.assertEqual(r["outcome_mark"], "inconclusive")
        self.assertIn("missing", {f["result"] for f in r["findings"]})

    def test_3_wrong_version_evidence_is_not_verified(self):
        ev = good_evidence()
        ev[1]["commit"] = "deadbeef00"  # CI result belongs to a different commit
        self.assertEqual(run(ev)["outcome_mark"], "not_verified")


class Adversarial(unittest.TestCase):
    def test_missing_production_health_is_inconclusive(self):
        self.assertEqual(run(drop("production_health"))["outcome_mark"], "inconclusive")

    def test_stale_evidence_is_inconclusive(self):
        ev = good_evidence(NOW - 7200)
        self.assertEqual(run(ev)["outcome_mark"], "inconclusive")

    def test_future_dated_evidence_is_not_accepted(self):
        ev = good_evidence(NOW + 86400)
        self.assertEqual(run(ev)["outcome_mark"], "inconclusive")

    def test_other_repo_is_not_verified(self):
        ev = good_evidence()
        ev[0]["repo"] = "evil/fork"
        self.assertEqual(run(ev)["outcome_mark"], "not_verified")

    def test_other_deployment_is_not_verified(self):
        ev = good_evidence()
        ev[3]["deployment_id"] = "dep-OTHER"
        self.assertEqual(run(ev)["outcome_mark"], "not_verified")

    def test_prohibited_path_is_not_verified(self):
        ev = good_evidence()
        ev[0]["changed_paths"] = ["src/pay.py", ".github/workflows/release.yml"]
        r = run(ev)
        self.assertEqual(r["outcome_mark"], "not_verified")
        self.assertTrue(any("prohibited" in f["detail"] for f in r["findings"]))

    def test_failing_ci_unhealthy_prod_unmerged(self):
        for idx, field, val in ((1, "status", "fail"), (3, "status", "unhealthy"), (0, "merged", False),
                                (2, "status", "failed")):
            ev = good_evidence()
            ev[idx][field] = val
            self.assertEqual(run(ev)["outcome_mark"], "not_verified", (idx, val))

    def test_pending_deployment_is_inconclusive(self):
        ev = good_evidence()
        ev[2]["status"] = "in_progress"
        self.assertEqual(run(ev)["outcome_mark"], "inconclusive")

    def test_rerun_pass_supersedes_older_fail(self):
        ev = good_evidence()
        old = dict(ev[1], observed_at=NOW - 600, status="fail")
        self.assertEqual(run(ev + [old])["outcome_mark"], "verified")

    def test_newer_fail_supersedes_older_pass(self):
        ev = good_evidence(NOW - 600)
        new = dict(ev[1], observed_at=NOW, status="fail")
        self.assertEqual(run(ev + [new])["outcome_mark"], "not_verified")

    def test_manifest_swapped_after_claim_is_not_verified(self):
        m = clone(MANIFEST)
        m["components"]["prompt"]["digest"] = "sha256:" + "b" * 64
        self.assertEqual(run(manifest=m)["outcome_mark"], "not_verified")

    def test_hiding_unknown_component_changes_stateprint(self):
        m = clone(MANIFEST)
        del m["components"]["model"]
        self.assertNotEqual(stateprint(m), stateprint(MANIFEST))

    def test_required_unknown_component_is_inconclusive(self):
        p = dict(POLICY, require_known_components=["model"])
        self.assertEqual(run(policy=p)["outcome_mark"], "inconclusive")

    def test_agent_id_mismatch(self):
        self.assertEqual(run(claim_=claim(agent_id="someone-else"))["outcome_mark"], "not_verified")

    def test_deterministic(self):
        self.assertEqual(run(), run())

    def test_limitations_always_present_and_unknowns_listed(self):
        r = run()
        self.assertGreaterEqual(len(r["limitations"]), 3)
        self.assertTrue(any("model" in l for l in r["limitations"]))

    def test_verified_does_not_claim_safety(self):
        self.assertTrue(any("not that the change is safe" in l for l in run()["limitations"]))


class KnownLimits(unittest.TestCase):
    """Documented non-goals: these tests prove what the verifier does NOT catch (see docs/limits.md)."""

    def test_lying_collector_is_not_detected(self):
        # If the evidence collector fabricates consistent evidence, the verifier cannot tell.
        self.assertEqual(run(good_evidence())["outcome_mark"], "verified")

    def test_unrequired_kinds_are_ignored(self):
        p = dict(POLICY, required=["ci"])
        self.assertEqual(run(drop("deployment"), policy=p)["outcome_mark"], "verified")


if __name__ == "__main__":
    unittest.main()
