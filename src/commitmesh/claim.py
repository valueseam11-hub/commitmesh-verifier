from . import schema as s


def parse_claim(d):
    s.keys(d, ["claim_id", "agent_id", "statement", "repo", "commit", "deployment_id", "agent_stateprint"],
           ["incident_id"], name="claim")
    s.text(d["claim_id"], "claim_id", 128, s.ID_RE)
    s.text(d["agent_id"], "agent_id", 128, s.ID_RE)
    s.text(d["statement"], "statement", 500)
    s.text(d["repo"], "repo", 201, s.REPO_RE)
    s.text(d["commit"], "commit", 64, s.SHA_RE)
    s.text(d["deployment_id"], "deployment_id", 128, s.ID_RE)
    s.text(d["agent_stateprint"], "agent_stateprint", 80, s.DIGEST_RE)
    if "incident_id" in d:
        s.text(d["incident_id"], "incident_id", 128, s.ID_RE)
    return d
