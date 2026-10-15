"""Signed ProofRecords (Ed25519). Verification needs only the record and a trusted public key."""
import base64
import binascii
import hashlib
import os
import secrets
import stat

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .canon import canonical_bytes, digest

SCHEMA = "commitmesh.proofrecord/1"
MARKS = {"verified", "inconclusive", "not_verified"}
SKEW = 300


def key_id(public_raw):
    return "sha256:" + hashlib.sha256(public_raw).hexdigest()


def _raw(pub):
    return pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def generate_keypair(private_path, public_path):
    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                            serialization.NoEncryption())
    fd = os.open(private_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)  # never overwrite
    with os.fdopen(fd, "wb") as f:
        f.write(pem)
    raw = _raw(key.public_key())
    with open(public_path, "w") as f:
        f.write(base64.b64encode(raw).decode() + "\n")
    return key_id(raw)


def load_private_key(path):
    if os.name == "posix" and stat.S_IMODE(os.stat(path).st_mode) & 0o077:
        raise PermissionError(f"refusing to read private key with group/world access: {path} (chmod 600)")
    with open(path, "rb") as f:
        key = serialization.load_pem_private_key(f.read(4096), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("private key must be Ed25519")
    return key


def decode_public_key(b64text):
    try:
        raw = base64.b64decode(b64text.strip(), validate=True)
    except (binascii.Error, ValueError):
        raise ValueError("public key is not valid base64") from None
    if len(raw) != 32:
        raise ValueError("public key must be 32 raw Ed25519 bytes")
    return raw


def sign_record(result, claim, private_key, now, validity_seconds=7 * 86400):
    payload = {
        "schema": SCHEMA,
        "record_id": secrets.token_hex(16),
        "claim_id": claim["claim_id"],
        "claim_digest": digest(claim),
        "agent_id": claim["agent_id"],
        "outcome_mark": result["outcome_mark"],
        "stateprint": result["stateprint"],
        "policy_id": result["policy_id"],
        "policy_hash": result["policy_hash"],
        "findings": result["findings"],
        "evidence_digests": result["evidence_digests"],
        "limitations": result["limitations"],
        "issued_at": now,
        "valid_until": now + validity_seconds,
        "key_id": key_id(_raw(private_key.public_key())),
    }
    sig = private_key.sign(canonical_bytes(payload))
    return {"payload": payload, "signature": base64.b64encode(sig).decode()}


def verify_record(record, public_raw, now, revoked_ids=(), expected_policy_hash=None):
    """Return (ok, reason, payload_or_None). Nothing in the payload is trusted before the signature checks out."""
    if not (isinstance(record, dict) and set(record) == {"payload", "signature"}
            and isinstance(record["payload"], dict) and isinstance(record["signature"], str)):
        return False, "bad_format", None
    payload = record["payload"]
    if payload.get("schema") != SCHEMA:
        return False, "bad_format", None
    if payload.get("key_id") != key_id(public_raw):
        return False, "key_mismatch", None
    try:
        sig = base64.b64decode(record["signature"], validate=True)
        msg = canonical_bytes(payload)
        Ed25519PublicKey.from_public_bytes(public_raw).verify(sig, msg)
    except (InvalidSignature, binascii.Error, ValueError, TypeError):
        return False, "bad_signature", None
    # Signature is valid: the fields below are now authentic (though still only as true as the evidence).
    issued, until = payload.get("issued_at"), payload.get("valid_until")
    ints = all(isinstance(x, int) and not isinstance(x, bool) for x in (issued, until))
    if not ints or payload.get("outcome_mark") not in MARKS:
        return False, "bad_format", None
    if issued > now + SKEW:
        return False, "not_yet_valid", payload
    if now > until:
        return False, "expired", payload
    if payload.get("record_id") in set(revoked_ids):
        return False, "revoked", payload
    if expected_policy_hash is not None and payload.get("policy_hash") != expected_policy_hash:
        return False, "policy_mismatch", payload
    return True, "ok", payload
