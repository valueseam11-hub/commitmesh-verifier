"""Evidence items as collected by adapters. Each kind has an exact allowed field set."""
from . import schema as s

_STATUS = {
    "ci": {"pass", "fail"},
    "deployment": {"success", "failed", "in_progress"},
    "production_health": {"healthy", "unhealthy", "unknown"},
}
_FIELDS = {
    "repository_change": ["repo", "commit", "merged", "changed_paths"],
    "ci": ["repo", "commit", "status"],
    "deployment": ["repo", "commit", "deployment_id", "status"],
    "production_health": ["deployment_id", "status"],
}


def _safe_path(p):
    s.text(p, "changed_path", 300)
    if p.startswith("/") or "\\" in p or ".." in p.split("/"):
        raise s.ValidationError("changed_path must be a repo-relative POSIX path")
    return p[2:] if p.startswith("./") else p


def parse_evidence_item(d):
    if not isinstance(d, dict) or d.get("kind") not in _FIELDS:
        raise s.ValidationError("evidence: unknown kind")
    kind = d["kind"]
    s.keys(d, ["kind", "source", "observed_at"] + _FIELDS[kind], name=f"evidence[{kind}]")
    s.text(d["source"], "source", 100)
    s.integer(d["observed_at"], "observed_at", 0, 4_102_444_800)
    if "repo" in d:
        s.text(d["repo"], "repo", 201, s.REPO_RE)
    if "commit" in d:
        s.text(d["commit"], "commit", 64, s.SHA_RE)
    if "deployment_id" in d:
        s.text(d["deployment_id"], "deployment_id", 128, s.ID_RE)
    if "status" in d and d["status"] not in _STATUS[kind]:
        raise s.ValidationError(f"evidence[{kind}]: bad status")
    if kind == "repository_change":
        if not isinstance(d["merged"], bool):
            raise s.ValidationError("merged must be boolean")
        paths = d["changed_paths"]
        if not isinstance(paths, list) or len(paths) > 2000:
            raise s.ValidationError("changed_paths: expected list up to 2000")
        d = dict(d, changed_paths=[_safe_path(p) for p in paths])
    return d


def parse_evidence(items):
    if not isinstance(items, list) or len(items) > 500:
        raise s.ValidationError("evidence: expected list up to 500 items")
    return [parse_evidence_item(i) for i in items]
