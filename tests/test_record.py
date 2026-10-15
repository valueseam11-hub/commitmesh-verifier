import base64
import json
import os
import stat
import unittest

from helpers import *  # noqa: F401,F403
from commitmesh.record import (decode_public_key, generate_keypair, load_private_key, sign_record, verify_record)


def _read(p):
    with open(p) as f:
        return f.read()


def make():
    d = tmpdir()
    priv, pub = keys(d.name)
    key = load_private_key(priv)
    res = run()
    rec = sign_record(res, claim(), key, NOW)
    return d, rec, decode_public_key(_read(pub)), res


class RecordIntegrity(unittest.TestCase):
    def test_valid_record_verifies_offline(self):
        d, rec, pub, _ = make()
        self.assertEqual(verify_record(rec, pub, NOW)[:2], (True, "ok"))

    def test_tampered_outcome_fails(self):
        d, rec, pub, _ = make()
        rec["payload"]["outcome_mark"] = "not_verified"
        self.assertEqual(verify_record(rec, pub, NOW)[:2], (False, "bad_signature"))

    def test_tampered_findings_fail(self):
        d, rec, pub, _ = make()
        rec["payload"]["findings"][0]["detail"] = "edited"
        self.assertEqual(verify_record(rec, pub, NOW)[1], "bad_signature")

    def test_swapped_signature_fails(self):
        d, rec, pub, _ = make()
        _, other, _, _ = make()
        rec["signature"] = other["signature"]
        self.assertEqual(verify_record(rec, pub, NOW)[1], "bad_signature")

    def test_wrong_key_fails(self):
        d, rec, _, _ = make()
        _, _, other_pub, _ = make()
        self.assertEqual(verify_record(rec, other_pub, NOW)[1], "key_mismatch")

    def test_key_id_swap_with_attacker_key_still_fails_for_trusted_key(self):
        d, rec, pub, _ = make()
        d2, rec2, pub2, _ = make()
        rec2["payload"]["key_id"] = rec["payload"]["key_id"]
        self.assertEqual(verify_record(rec2, pub, NOW)[1], "bad_signature")

    def test_expired_fails(self):
        d, rec, pub, _ = make()
        self.assertEqual(verify_record(rec, pub, NOW + 8 * 86400)[1], "expired")

    def test_future_issued_fails(self):
        d, rec, pub, _ = make()
        self.assertEqual(verify_record(rec, pub, NOW - 3600)[1], "not_yet_valid")

    def test_revoked_fails(self):
        d, rec, pub, _ = make()
        rid = rec["payload"]["record_id"]
        self.assertEqual(verify_record(rec, pub, NOW, revoked_ids=[rid])[1], "revoked")

    def test_policy_change_detected(self):
        d, rec, pub, res = make()
        self.assertEqual(verify_record(rec, pub, NOW, expected_policy_hash=res["policy_hash"])[0], True)
        self.assertEqual(verify_record(rec, pub, NOW, expected_policy_hash="sha256:" + "0" * 64)[1], "policy_mismatch")

    def test_malformed_records_fail_closed(self):
        d, rec, pub, _ = make()
        for bad in (None, [], {}, {"payload": {}, "signature": "x"}, {"payload": rec["payload"], "signature": 5},
                    dict(rec, extra=1), {"payload": dict(rec["payload"], schema="other"), "signature": rec["signature"]}):
            self.assertFalse(verify_record(bad, pub, NOW)[0])

    def test_garbage_signature_does_not_raise(self):
        d, rec, pub, _ = make()
        for sig in ("!!!notbase64", "", base64.b64encode(b"short").decode()):
            self.assertEqual(verify_record(dict(rec, signature=sig), pub, NOW)[1], "bad_signature")

    def test_record_for_not_verified_is_still_authentic(self):
        d = tmpdir(); priv, pub = keys(d.name)
        rec = sign_record(run(drop("ci")), claim(), load_private_key(priv), NOW)
        ok, reason, payload = verify_record(rec, decode_public_key(_read(pub)), NOW)
        self.assertTrue(ok); self.assertEqual(payload["outcome_mark"], "inconclusive")


class KeyHandling(unittest.TestCase):
    @unittest.skipUnless(os.name == "posix", "posix permissions")
    def test_private_key_is_0600_and_loose_perms_refused(self):
        d = tmpdir(); priv, _ = keys(d.name)
        self.assertEqual(stat.S_IMODE(os.stat(priv).st_mode), 0o600)
        os.chmod(priv, 0o644)
        with self.assertRaises(PermissionError):
            load_private_key(priv)

    def test_keygen_never_overwrites(self):
        d = tmpdir(); priv, pub = keys(d.name)
        with self.assertRaises(FileExistsError):
            generate_keypair(priv, pub)

    def test_bad_public_key_rejected(self):
        for bad in ("not base64!!", base64.b64encode(b"x" * 31).decode()):
            with self.assertRaises(ValueError):
                decode_public_key(bad)


if __name__ == "__main__":
    unittest.main()
