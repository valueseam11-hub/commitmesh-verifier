"""Agent Manifest + Stateprint. A digest proves the manifest as supplied, not the whole agent."""
from . import schema as s
from .canon import digest

STATUSES = {"known_and_hashed", "provider_attested", "unknown", "not_verified"}
KNOWN = {"known_and_hashed", "provider_attested"}


def parse_manifest(d):
    s.keys(d, ["agent_id", "version", "components"], name="manifest")
    s.text(d["agent_id"], "agent_id", 128, s.ID_RE)
    s.text(d["version"], "version", 64)
    comps = d["components"]
    if not isinstance(comps, dict) or not 1 <= len(comps) <= 64:
        raise s.ValidationError("components: expected 1-64 entries")
    for name, c in comps.items():
        s.text(name, "component name", 128, s.ID_RE)
        s.keys(c, ["status"], ["digest", "ref"], name=f"component {name}")
        if c["status"] not in STATUSES:
            raise s.ValidationError(f"component {name}: bad status")
        if c["status"] in KNOWN:
            s.text(c.get("digest"), f"{name}.digest", 80, s.DIGEST_RE)
        elif "digest" in c:
            raise s.ValidationError(f"component {name}: unknown/unverified must not carry a digest")
        if "ref" in c:
            s.text(c["ref"], f"{name}.ref", 300)
    return d


def stateprint(m):
    # Unknown components are part of the hashed input, so hiding one changes the stateprint.
    return digest({"agent_id": m["agent_id"], "version": m["version"], "components": m["components"]})


def unknown_components(m):
    return sorted(n for n, c in m["components"].items() if c["status"] not in KNOWN)
