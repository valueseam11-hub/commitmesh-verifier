"""Deterministic verification. Same inputs + same `now` => same outcome. No network, no models."""
import fnmatch
import hmac

from .canon import digest
from .manifest import KNOWN, stateprint, unknown_components
from .policy import policy_hash

CLOCK_SKEW = 300  # seconds of future-dated evidence tolerated

STATIC_LIMITS = [
    "Evidence is trusted as supplied by the collector; a compromised source system or collector is not detected.",
    "A matching digest proves the manifest as supplied, not the completeness of the agent or its future behavior.",
    "'verified' means the required evidence supports the claim under this policy, not that the change is safe.",
]


def _commit_match(a, b):
    return a.startswith(b) or b.startswith(a)


def _binds(e, claim):
    if "repo" in e and e["repo"] != claim["repo"]:
        return False
    if "deployment_id" in e and e["deployment_id"] != claim["deployment_id"]:
        return False
    if "commit" in e and not _commit_match(e["commit"], claim["commit"]):
        return False
    return True


def _judge(kind, e, policy):
    """Return (result, detail) for one evidence item already bound to the claim and fresh."""
    if kind == "repository_change":
        if not e["merged"]:
            return "contradicted", "change is not merged into the base branch"
        for pat in policy.get("prohibited_paths", []):
            hit = [p for p in e["changed_paths"] if fnmatch.fnmatchcase(p, pat)]
            if hit:
                return "contradicted", f"prohibited path changed: {hit[0]}"
    elif kind == "ci" and e["status"] == "fail":
        return "contradicted", "CI reports failure"
    elif kind == "deployment":
        if e["status"] == "failed":
            return "contradicted", "deployment failed"
        if e["status"] == "in_progress":
            return "pending", "deployment still in progress"
    elif kind == "production_health":
        if e["status"] == "unhealthy":
            return "contradicted", "production health is unhealthy"
        if e["status"] == "unknown":
            return "pending", "production health is unknown"
    return "verified", "evidence supports the claim"


def _eval_kind(kind, evidence, claim, policy, now, used, limits):
    mine = [e for e in evidence if e["kind"] == kind]
    if not mine:
        return "missing", "no evidence supplied"
    related = [e for e in mine if _binds(e, claim)]
    if len(related) < len(mine):
        limits.append(f"{len(mine) - len(related)} {kind} evidence item(s) for a different version were ignored.")
    if not related:
        return "wrong_version", "evidence refers to a different repo, commit or deployment"
    age = policy["max_evidence_age_seconds"]
    fresh = [e for e in related if e["observed_at"] <= now + CLOCK_SKEW and now - e["observed_at"] <= age]
    if not fresh:
        return "stale", "evidence is older than the policy allows or future-dated"
    newest = max(e["observed_at"] for e in fresh)
    latest = [e for e in fresh if e["observed_at"] == newest]
    used.extend(latest)
    verdicts = [_judge(kind, e, policy) for e in latest]
    for want in ("contradicted", "pending"):
        for r, d in verdicts:
            if r == want:
                return r, d
    return "verified", verdicts[0][1]


def verify(manifest, claim, policy, evidence, now):
    findings, limits, used = [], list(STATIC_LIMITS), []
    sp = stateprint(manifest)

    def add(kind, result, detail):
        findings.append({"kind": kind, "result": result, "detail": detail})

    if claim["agent_id"] != manifest["agent_id"]:
        add("binding", "contradicted", "claim agent_id does not match manifest")
    elif not hmac.compare_digest(sp, claim["agent_stateprint"]):
        add("binding", "contradicted", "claim stateprint does not match the manifest")
    else:
        add("binding", "verified", "claim is bound to this manifest")

    for name in policy.get("require_known_components", []):
        c = manifest["components"].get(name)
        if c is None or c["status"] not in KNOWN:
            add(f"component:{name}", "unknown_component", "required component is not known/attested")
    unk = unknown_components(manifest)
    if unk:
        limits.append(f"Components not verified in the manifest: {', '.join(unk)}.")

    for kind in policy["required"]:
        r, d = _eval_kind(kind, evidence, claim, policy, now, used, limits)
        add(kind, r, d)

    results = {f["result"] for f in findings}
    if results & {"contradicted", "wrong_version"}:
        mark = "not_verified"
    elif results == {"verified"}:
        mark = "verified"
    else:
        mark = "inconclusive"
    return {
        "outcome_mark": mark,
        "stateprint": sp,
        "policy_id": policy["policy_id"],
        "policy_hash": policy_hash(policy),
        "findings": findings,
        "limitations": limits,
        "evidence_digests": sorted(digest(e) for e in used),
    }
