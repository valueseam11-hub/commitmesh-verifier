import io
import json
import os
import unittest
from contextlib import redirect_stdout, redirect_stderr

from helpers import *  # noqa: F401,F403
from commitmesh import cli, github, server
from commitmesh.record import decode_public_key, load_private_key, sign_record


def call(argv):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = cli.main(argv)
    return code, out.getvalue(), err.getvalue()


class CLI(unittest.TestCase):
    def setUp(self):
        self.d = tmpdir(); p = self.d.name
        self.priv, self.pub = keys(p)
        self.files = dict(manifest=write(p, "m.json", MANIFEST), claim=write(p, "c.json", claim()),
                          policy=write(p, "p.json", POLICY), out=os.path.join(p, "rec.json"))

    def _verify(self, evidence):
        ev = write(self.d.name, "e.json", evidence)
        return call(["verify", "--manifest", self.files["manifest"], "--claim", self.files["claim"],
                     "--policy", self.files["policy"], "--evidence", ev, "--key", self.priv,
                     "--out", self.files["out"]])

    def test_exit_codes_map_to_outcomes(self):
        self.assertEqual(self._verify(good_evidence())[0], 0)
        self.assertEqual(self._verify(drop("deployment"))[0], 10)
        bad = good_evidence(); bad[1]["status"] = "fail"
        self.assertEqual(self._verify(bad)[0], 11)

    def test_end_to_end_offline_check(self):
        self._verify(good_evidence())
        code, out, _ = call(["check", "--record", self.files["out"], "--public-key", self.pub,
                             "--policy", self.files["policy"], "--require-verified"])
        self.assertEqual(code, 0, out)

    def test_check_require_verified_blocks_inconclusive(self):
        self._verify(drop("ci"))
        code, _, _ = call(["check", "--record", self.files["out"], "--public-key", self.pub, "--require-verified"])
        self.assertEqual(code, 3)

    def test_check_detects_tampered_file(self):
        self._verify(good_evidence())
        rec = json.load(open(self.files["out"])); rec["payload"]["outcome_mark"] = "verified"; rec["payload"]["agent_id"] = "x"
        json.dump(rec, open(self.files["out"], "w"))
        self.assertEqual(call(["check", "--record", self.files["out"], "--public-key", self.pub])[0], 1)

    def test_check_honours_revocation_file(self):
        self._verify(good_evidence())
        rid = json.load(open(self.files["out"]))["payload"]["record_id"]
        rv = write(self.d.name, "rev.json", [rid])
        self.assertEqual(call(["check", "--record", self.files["out"], "--public-key", self.pub, "--revoked", rv])[0], 1)

    def test_bad_input_exits_2_without_traceback(self):
        bad = write(self.d.name, "bad.json", {"nope": 1})
        code, _, err = call(["stateprint", "--manifest", bad])
        self.assertEqual(code, 2); self.assertNotIn("Traceback", err)

    def test_loose_key_permissions_refused(self):
        os.chmod(self.priv, 0o644)
        self.assertEqual(self._verify(good_evidence())[0], 2)


class Server(unittest.TestCase):
    def setUp(self):
        d = tmpdir(); self.d = d
        priv, pub = keys(d.name)
        self.rec = sign_record(run(), claim(), load_private_key(priv), NOW)
        self.pub = open(pub).read().strip()

    def body(self, **kw):
        return json.dumps(dict({"record": self.rec, "public_key": self.pub}, **kw)).encode()

    def test_valid_record(self):
        r = server.check_body(self.body(), NOW)
        self.assertTrue(r["valid"]); self.assertEqual(r["outcome_mark"], "verified")

    def test_tampered_record_invalid(self):
        self.rec["payload"]["outcome_mark"] = "not_verified"
        self.assertFalse(server.check_body(self.body(), NOW)["valid"])

    def test_malformed_and_unknown_fields_rejected(self):
        for bad in (b"{}", b"[]", b"not json", self.body(extra=1), b'{"record":1,"public_key":"AA"}'):
            with self.assertRaises(ValueError):
                server.check_body(bad, NOW)

    def test_server_has_no_signing_capability(self):
        self.assertFalse(hasattr(server, 'sign_record'))
        self.assertFalse(hasattr(server, 'load_private_key'))


class GitHubAdapter(unittest.TestCase):
    def fetch_factory(self, files=None, status="behind", runs=None, total=None):
        def fetch(path):
            if "/compare/" in path:
                return {"status": status}
            if "/check-runs" in path:
                r = runs if runs is not None else [{"status": "completed", "conclusion": "success"}]
                return {"total_count": total or len(r), "check_runs": r}
            return {"sha": COMMIT, "files": files if files is not None else [{"filename": "src/pay.py"}]}
        return fetch

    def test_repository_change_and_merge_detection(self):
        e = github.repository_change("acme/payments", COMMIT, "main", self.fetch_factory(), NOW)
        self.assertTrue(e["merged"]); self.assertEqual(e["changed_paths"], ["src/pay.py"])
        e = github.repository_change("acme/payments", COMMIT, "main", self.fetch_factory(status="ahead"), NOW)
        self.assertFalse(e["merged"])

    def test_truncated_file_list_is_refused(self):
        with self.assertRaises(github.AdapterError):
            github.repository_change("acme/payments", COMMIT, "main",
                                     self.fetch_factory(files=[{"filename": f"f{i}"} for i in range(300)]), NOW)

    def test_ci_incomplete_or_paginated_is_missing_not_pass(self):
        f = self.fetch_factory(runs=[{"status": "in_progress"}])
        self.assertIsNone(github.ci("acme/payments", COMMIT, f, NOW))
        f = self.fetch_factory(runs=[{"status": "completed", "conclusion": "success"}], total=150)
        self.assertIsNone(github.ci("acme/payments", COMMIT, f, NOW))

    def test_ci_failure_detected(self):
        f = self.fetch_factory(runs=[{"status": "completed", "conclusion": "failure"}])
        self.assertEqual(github.ci("acme/payments", COMMIT, f, NOW)["status"], "fail")

    def test_adapter_output_passes_evidence_validation_and_engine(self):
        from commitmesh.evidence import parse_evidence
        f = self.fetch_factory()
        items = [github.repository_change("acme/payments", COMMIT, "main", f, NOW), github.ci("acme/payments", COMMIT, f, NOW)]
        parse_evidence(items)

    def test_injection_in_repo_or_branch_rejected(self):
        from commitmesh.schema import ValidationError
        for repo, br in (("a/b/../../x", "main"), ("acme/payments", "main?x=1"), ("acme/pay ments", "main")):
            with self.assertRaises(ValidationError):
                github.repository_change(repo, COMMIT, br, self.fetch_factory(), NOW)

    def test_fetch_refuses_unexpected_paths(self):
        f = github.make_fetch()
        for p in ("/user", "/repos/a/b/../../../x", "https://evil.example/x"):
            with self.assertRaises(github.AdapterError):
                f(p)


if __name__ == "__main__":
    unittest.main()
