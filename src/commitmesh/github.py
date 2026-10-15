"""Read-only GitHub evidence adapter. HTTPS to api.github.com only; token from env, never logged."""
import json
import re
import urllib.request

from . import schema as s

API_HOST = "https://api.github.com"
MAX_BYTES = 2_000_000
_PATH_RE = re.compile(r"^/repos/[A-Za-z0-9._\-]+/[A-Za-z0-9._\-]+/[A-Za-z0-9._\-/]+$")


class AdapterError(RuntimeError):
    pass


def make_fetch(token=None, timeout=10):
    def fetch(path):
        if not _PATH_RE.match(path) or ".." in path:
            raise AdapterError("refusing to request an unexpected API path")
        req = urllib.request.Request(API_HOST + path, headers={
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "commitmesh/0.1",
            **({"Authorization": f"Bearer {token}"} if token else {}),
        })
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310 (fixed https host)
                if not r.geturl().startswith(API_HOST + "/"):
                    raise AdapterError("unexpected redirect")
                data = r.read(MAX_BYTES + 1)
        except OSError as e:
            raise AdapterError(f"GitHub request failed: {type(e).__name__}") from None
        if len(data) > MAX_BYTES:
            raise AdapterError("GitHub response too large")
        return json.loads(data)
    return fetch


def repository_change(repo, commit, base_branch, fetch, now):
    s.text(repo, "repo", 201, s.REPO_RE)
    s.text(commit, "commit", 64, s.SHA_RE)
    s.text(base_branch, "base_branch", 100, s.BRANCH_RE)
    c = fetch(f"/repos/{repo}/commits/{commit}")
    files = c.get("files", [])
    if len(files) >= 300:
        raise AdapterError("commit touches >=300 files; GitHub truncates the list, cannot check prohibited paths")
    cmp_ = fetch(f"/repos/{repo}/compare/{base_branch}...{commit}")
    merged = cmp_.get("status") in ("behind", "identical")
    return {"kind": "repository_change", "source": "github", "observed_at": now, "repo": repo,
            "commit": c["sha"], "merged": merged, "changed_paths": [f["filename"] for f in files]}


def ci(repo, commit, fetch, now):
    s.text(repo, "repo", 201, s.REPO_RE)
    s.text(commit, "commit", 64, s.SHA_RE)
    d = fetch(f"/repos/{repo}/commits/{commit}/check-runs?per_page=100")
    runs = d.get("check_runs", [])
    if not runs or d.get("total_count", 0) > len(runs) or any(r.get("status") != "completed" for r in runs):
        return None  # incomplete or paginated => treat as missing evidence (inconclusive), never as pass
    ok = all(r.get("conclusion") in ("success", "neutral", "skipped") for r in runs)
    return {"kind": "ci", "source": "github-checks", "observed_at": now, "repo": repo,
            "commit": commit, "status": "pass" if ok else "fail"}
