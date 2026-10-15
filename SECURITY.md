# Security

Design rules: standard cryptography only (Ed25519 via `cryptography`), canonical JSON for everything signed, strict schemas (unknown fields, duplicate keys, NaN, oversize input all rejected), fail-closed verification, no dynamic code or YAML loading, no network in the verification engine, signing keys never on the hosted service, workflow inputs passed via env vars not shell interpolation.

Report vulnerabilities privately to the maintainers (add a contact address before publishing). Do not open public issues for security problems.
