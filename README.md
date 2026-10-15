# CommitMesh

Checks whether an AI agent's **claimed outcome** is backed by **evidence bound to the exact version**, and issues a **signed, offline-verifiable record**.

Results: `verified`, `inconclusive` (missing/stale/pending evidence), `not_verified` (contradicted or wrong-version evidence). There is no "safe" score.

## Try it
```bash
export PYTHONPATH=src
python -m commitmesh.cli keygen --private key.pem --public key.pub
python -m commitmesh.cli stateprint --manifest examples/manifest.json   # put this value in your claim
python -m commitmesh.cli collect-github --repo OWNER/REPO --commit SHA --out evidence-gh.json   # needs GITHUB_TOKEN
python -m commitmesh.cli verify --manifest examples/manifest.json --claim claim.json \
  --policy examples/policy.json --evidence evidence-gh.json --evidence evidence-deploy.json \
  --key key.pem --out record.json            # exit 0 verified | 10 inconclusive | 11 not_verified | 2 error
python -m commitmesh.cli check --record record.json --public-key key.pub --require-verified
```
Tests: `PYTHONPATH=src:tests python -m unittest discover -s tests -v`

See `docs/limits.md` for what this does not catch, and `SECURITY.md`.
