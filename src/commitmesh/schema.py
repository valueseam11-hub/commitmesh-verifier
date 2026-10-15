"""Strict input validation. Unknown fields, oversize values and duplicate JSON keys are rejected."""
import json
import re

MAX_JSON_BYTES = 1_000_000


class ValidationError(ValueError):
    pass


ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:\-]{0,127}$")
REPO_RE = re.compile(r"^[A-Za-z0-9._\-]{1,100}/[A-Za-z0-9._\-]{1,100}$")
SHA_RE = re.compile(r"^[0-9a-f]{7,64}$")
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
BRANCH_RE = re.compile(r"^[A-Za-z0-9._\-/]{1,100}$")


def _no_dupes(pairs):
    d = {}
    for k, v in pairs:
        if k in d:
            raise ValidationError(f"duplicate JSON key: {k!r}")
        d[k] = v
    return d


def _no_const(name):
    raise ValidationError(f"non-finite number not allowed: {name}")


def loads_strict(data):
    if isinstance(data, str):
        data = data.encode("utf-8")
    if len(data) > MAX_JSON_BYTES:
        raise ValidationError("JSON input too large")
    try:
        return json.loads(data, object_pairs_hook=_no_dupes, parse_constant=_no_const)
    except json.JSONDecodeError as e:
        raise ValidationError(f"invalid JSON: {e.msg}") from None
    except UnicodeDecodeError:
        raise ValidationError("input is not valid UTF-8") from None
    except RecursionError:
        raise ValidationError("JSON nesting too deep") from None


def load_json_file(path):
    with open(path, "rb") as f:
        data = f.read(MAX_JSON_BYTES + 1)
    return loads_strict(data)


def keys(d, required, optional=(), name="object"):
    if not isinstance(d, dict):
        raise ValidationError(f"{name} must be an object")
    missing = set(required) - d.keys()
    extra = d.keys() - set(required) - set(optional)
    if missing:
        raise ValidationError(f"{name}: missing {sorted(missing)}")
    if extra:
        raise ValidationError(f"{name}: unknown fields {sorted(extra)}")


def text(v, name, maxlen=500, pattern=None):
    if not isinstance(v, str) or not v or len(v) > maxlen or "\x00" in v:
        raise ValidationError(f"{name}: expected non-empty string up to {maxlen} chars")
    if pattern is not None and not pattern.match(v):
        raise ValidationError(f"{name}: invalid format")
    return v


def integer(v, name, lo, hi):
    if isinstance(v, bool) or not isinstance(v, int) or not lo <= v <= hi:
        raise ValidationError(f"{name}: expected integer in [{lo}, {hi}]")
    return v
