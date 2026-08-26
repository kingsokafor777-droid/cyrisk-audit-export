# Architecture

The builder validates a supplied `PackageRequest`, excludes any raw-evidence surface by contract,
sorts reference records, and produces a ZIP with exactly `manifest.json` and `verification.json`.
Both files use canonical JSON. The verifier checks ZIP member names, fixed timestamps, canonical
JSON, manifest hash, and verification-record correspondence.

| State | Output |
|---|---|
| Valid metadata-only request | A deterministic audit-preparation package. |
| Missing mandatory redaction declarations | Fail-closed validation error. |
| Altered member, noncanonical JSON, timestamp drift, or manifest mismatch | Offline verification failure. |

The output documents what metadata was supplied. It does not determine whether supplied data is
true, complete, effective, accepted by an auditor, or sufficient for any compliance conclusion.
