# Threat Model

| Threat | Example | Mitigation and boundary |
|---|---|---|
| Payload leakage | A source locator or raw evidence crosses into the archive. | Strict metadata-only model; unknown fields fail closed. |
| Artifact drift | Equivalent input produces unequal package bytes. | Canonical JSON, lexical ordering, fixed timestamp, fixed ZIP mode. |
| Integrity overclaim | A package hash is mistaken for source truth. | Documentation and verifier state only record/package integrity. |
| Policy omission | Sensitive field names are not declared for redaction. | Required redaction policy vocabulary and manifest inclusion. |
| Certification claim | Package is described as a completed audit. | Source-release docs deny audit opinion/certification. |
