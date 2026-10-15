import argparse
import json
import os
import sys
import tempfile
import time

from . import __version__, github, schema as s
from .claim import parse_claim
from .engine import verify
from .evidence import parse_evidence
from .manifest import parse_manifest, stateprint
from .policy import parse_policy, policy_hash
from .record import (decode_public_key, generate_keypair, load_private_key, sign_record, verify_record)

EXIT = {"verified": 0, "inconclusive": 10, "not_verified": 11}


def _atomic_write(path, text):
    d = os.path.dirname(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".commitmesh-")
    with os.fdopen(fd, "w") as f:
        f.write(text)
    os.replace(tmp, path)


def cmd_keygen(a):
    kid = generate_keypair(a.private, a.public)
    print(json.dumps({"key_id": kid, "private": a.private, "public": a.public}))
    return 0


def cmd_stateprint(a):
    print(stateprint(parse_manifest(s.load_json_file(a.manifest))))
    return 0


def cmd_collect_github(a):
    now = int(time.time())
    fetch = github.make_fetch(os.environ.get("GITHUB_TOKEN"))
    items = [github.repository_change(a.repo, a.commit, a.base_branch, fetch, now)]
    ci_item = github.ci(a.repo, a.commit, fetch, now)
    if ci_item:
        items.append(ci_item)
    _atomic_write(a.out, json.dumps(items, indent=2) + "\n")
    print(f"wrote {len(items)} evidence item(s) to {a.out}")
    return 0


def cmd_verify(a):
    manifest = parse_manifest(s.load_json_file(a.manifest))
    claim = parse_claim(s.load_json_file(a.claim))
    policy = parse_policy(s.load_json_file(a.policy))
    evidence = []
    for path in a.evidence:
        evidence += parse_evidence(s.load_json_file(path))
    now = int(time.time())
    result = verify(manifest, claim, policy, evidence, now)
    record = sign_record(result, claim, load_private_key(a.key), now)
    _atomic_write(a.out, json.dumps(record, indent=2) + "\n")
    print(json.dumps({"outcome_mark": result["outcome_mark"], "record": a.out,
                      "findings": result["findings"]}, indent=2))
    return EXIT[result["outcome_mark"]]


def cmd_check(a):
    record = s.load_json_file(a.record)
    with open(a.public_key) as f:
        pub = decode_public_key(f.read(1024))
    revoked = s.load_json_file(a.revoked) if a.revoked else []
    if not isinstance(revoked, list) or not all(isinstance(x, str) for x in revoked):
        raise s.ValidationError("revoked file must be a JSON list of record_id strings")
    exp = policy_hash(parse_policy(s.load_json_file(a.policy))) if a.policy else None
    ok, reason, payload = verify_record(record, pub, int(time.time()), revoked, exp)
    mark = payload.get("outcome_mark") if payload else None
    print(json.dumps({"valid": ok, "reason": reason, "outcome_mark": mark,
                      "record_id": (payload or {}).get("record_id")}))
    if not ok:
        return 1
    return 3 if (a.require_verified and mark != "verified") else 0


def build_parser():
    p = argparse.ArgumentParser(prog="commitmesh")
    p.add_argument("--version", action="version", version=__version__)
    sub = p.add_subparsers(dest="cmd", required=True)
    k = sub.add_parser("keygen"); k.add_argument("--private", required=True); k.add_argument("--public", required=True)
    k.set_defaults(fn=cmd_keygen)
    sp = sub.add_parser("stateprint"); sp.add_argument("--manifest", required=True); sp.set_defaults(fn=cmd_stateprint)
    g = sub.add_parser("collect-github")
    for n in ("--repo", "--commit", "--out"):
        g.add_argument(n, required=True)
    g.add_argument("--base-branch", default="main"); g.set_defaults(fn=cmd_collect_github)
    v = sub.add_parser("verify")
    for n in ("--manifest", "--claim", "--policy", "--key", "--out"):
        v.add_argument(n, required=True)
    v.add_argument("--evidence", action="append", required=True); v.set_defaults(fn=cmd_verify)
    c = sub.add_parser("check")
    c.add_argument("--record", required=True); c.add_argument("--public-key", required=True)
    c.add_argument("--revoked"); c.add_argument("--policy"); c.add_argument("--require-verified", action="store_true")
    c.set_defaults(fn=cmd_check)
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        return args.fn(args)
    except (s.ValidationError, github.AdapterError, OSError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)  # message only; never a traceback (could echo secrets)
        return 2


if __name__ == "__main__":
    sys.exit(main())
