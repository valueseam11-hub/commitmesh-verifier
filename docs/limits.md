# What CommitMesh does NOT do

- **Does not detect a lying evidence source or collector.** If CI, the repo host, or your collector reports false but consistent data, the record will say `verified`. A signature proves the record is authentic, not that the world is true.
- **`verified` is not "safe".** It means the required evidence supports the claim under the stated policy.
- **The stateprint covers only the manifest you supply.** Closed-model weights, hidden provider prompts and training data cannot be hashed; they are recorded as `unknown` and listed in the record's limitations.
- **Revocation needs a fresh list.** `check --revoked` only knows the revocation list you give it. An offline verifier cannot learn about revocations it was never shown.
- **The public key must be obtained out of band.** The hosted checker verifies against the key in the request; it proves "signed by this key id", not "signed by whom you trust".
- **GitHub adapter:** commits touching 300+ files are refused (the API truncates the list); incomplete or paginated check runs count as missing evidence, never as a pass. Branch merge detection uses the compare API against one named base branch.
- **Prohibited-path patterns are case-sensitive** `fnmatch` patterns; write explicit patterns for case-insensitive filesystems.
- **Hosted checker has no per-client rate limiting** (only a global concurrency cap and a 128 KB body cap). Put it behind a gateway if exposed widely.
- **Private keys are plain PEM files (0600).** For production use a KMS/HSM and customer-controlled keys.
- The GitHub adapter was unit-tested with mocked responses only; it has not been run against the live API in the build sandbox.
