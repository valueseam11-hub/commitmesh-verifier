"""ProofRule: versioned acceptance policy (JSON, not YAML, to avoid unsafe loaders)."""
from . import schema as s
from .canon import digest

KINDS = ("repository_change", "ci", "deployment", "production_health")


def parse_policy(d):
    s.keys(d, ["policy_id", "version", "required", "max_evidence_age_seconds"],
           ["prohibited_paths", "require_known_components"], name="policy")
    s.text(d["policy_id"], "policy_id", 128, s.ID_RE)
    s.integer(d["version"], "version", 1, 10**6)
    req = d["required"]
    if (not isinstance(req, list) or not req or len(set(req)) != len(req)
            or any(k not in KINDS for k in req)):
        raise s.ValidationError(f"required: non-empty unique subset of {KINDS}")
    s.integer(d["max_evidence_age_seconds"], "max_evidence_age_seconds", 60, 30 * 86400)
    for field in ("prohibited_paths", "require_known_components"):
        v = d.get(field, [])
        if not isinstance(v, list) or len(v) > 50:
            raise s.ValidationError(f"{field}: expected list of up to 50")
        for item in v:
            s.text(item, field, 200)
    return d


def policy_hash(p):
    return digest(p)
