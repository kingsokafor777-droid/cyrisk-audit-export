# Release Governance

## Candidate: v0.1.0

| Item | Verified local value |
|---|---|
| Package | `cyrisk-audit-export` v0.1.0 |
| Core compatibility pin | `cyrisk-core` commit `4d68f385ef382a6420466dff0196244a2c915f1f` |
| Package schema | `cyrisk.audit-export/v1` |
| Synthetic request SHA-256 | `940c324d1aa8cd9bea6040b8eebd98ba896d0a296fb0308bafefdc69818f3be0` |
| Expected-result SHA-256 | `cf141b0fd246fa42ddfbb8f80e7c368e0e41de771e68674ee9f4791883134fb3` |
| Local behavioral result | `make check` passed: fixture reproducibility, Ruff, strict mypy, 14 tests, and 98.10% branch-aware coverage |
| Wheel SHA-256 | `55659e8adf669a90ad3a4d163376d4841edfe05bad6d49e336715fd65a9dc1ce` |

Publication remains approval-gated. After explicit approval, the procedure must create the public
repository, tag the reviewed commit, attach the verified wheel, wait for successful hosted
`Quality`, Python 3.10–3.13, and `Analyze Python` checks, retrieve exact check contexts, apply the
protected-main policy, and synchronize the profile and program ledger.

The package and its verifier speak only to declared metadata and archive integrity. They do not
collect or reveal source evidence, perform redaction execution, verify source truth, produce an
audit opinion, certify compliance, validate authority, or make a risk/remediation decision. A
successful CodeQL workflow must not be used to claim a code-scanning-alert count without an
accessible platform result.
