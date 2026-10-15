"""Canonical JSON + hashing. Every signature/digest is computed over these bytes."""
import hashlib
import json


def canonical_bytes(obj) -> bytes:
    # sort_keys + fixed separators + ASCII-only => one byte string per logical value.
    # allow_nan=False rejects NaN/Infinity, which have no canonical JSON form.
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def digest(obj) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(obj)).hexdigest()
