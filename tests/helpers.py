import copy
import json
import os
import tempfile
import time

from commitmesh.engine import verify
from commitmesh.manifest import stateprint
from commitmesh.record import generate_keypair, load_private_key

NOW = int(time.time())
D = "sha256:" + "a" * 64
MANIFEST = {"agent_id": "fixer-1", "version": "1.0.0", "components": {
    "prompt": {"status": "known_and_hashed", "digest": D},
    "tools": {"status": "known_and_hashed", "digest": D},
    "model": {"status": "unknown"},
}}
POLICY = {"policy_id": "production-fix", "version": 1,
          "required": ["repository_change", "ci", "deployment", "production_health"],
          "max_evidence_age_seconds": 3600, "prohibited_paths": [".github/workflows/*", "secrets/*"]}
COMMIT = "abc1234def5678"


def claim(**kw):
    c = {"claim_id": "claim-381", "agent_id": "fixer-1", "statement": "Fixed INC-381 and deployed.",
         "repo": "acme/payments", "commit": COMMIT, "deployment_id": "dep-9",
         "agent_stateprint": stateprint(MANIFEST)}
    c.update(kw)
    return c


def good_evidence(now=NOW):
    return [
        {"kind": "repository_change", "source": "github", "observed_at": now, "repo": "acme/payments",
         "commit": COMMIT, "merged": True, "changed_paths": ["src/pay.py"]},
        {"kind": "ci", "source": "ci", "observed_at": now, "repo": "acme/payments", "commit": COMMIT, "status": "pass"},
        {"kind": "deployment", "source": "railway", "observed_at": now, "repo": "acme/payments",
         "commit": COMMIT, "deployment_id": "dep-9", "status": "success"},
        {"kind": "production_health", "source": "monitor", "observed_at": now, "deployment_id": "dep-9",
         "status": "healthy"},
    ]


def run(evidence=None, claim_=None, policy=None, manifest=None, now=NOW):
    return verify(manifest or MANIFEST, claim_ or claim(), policy or POLICY,
                  good_evidence(now) if evidence is None else evidence, now)


def drop(kind):
    return [e for e in good_evidence() if e["kind"] != kind]


def tmpdir():
    return tempfile.TemporaryDirectory()


def keys(d):
    priv, pub = os.path.join(d, "k.pem"), os.path.join(d, "k.pub")
    generate_keypair(priv, pub)
    return priv, pub


def write(d, name, obj):
    p = os.path.join(d, name)
    with open(p, "w") as f:
        json.dump(obj, f)
    return p


def clone(x):
    return copy.deepcopy(x)
