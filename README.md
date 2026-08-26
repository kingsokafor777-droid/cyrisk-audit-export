# Cyrisk Audit Export

> **Deterministic, payload-blind audit-preparation package metadata and offline verification—not evidence collection, an audit opinion, compliance certification, authority validation, or a remediation workflow.**

`cyrisk-audit-export` builds byte-reproducible ZIP archives containing a canonical manifest and
verification record. Inputs are supplied metadata IDs, SHA-256 hashes, lifecycle dates, source
classes, and a declared redaction policy. The package never accepts raw evidence bytes, payload
locators, credentials, or source-system connections.

| Component | Deterministic behavior | Explicit boundary |
|---|---|---|
| Builder | Canonicalizes validated metadata and writes fixed-timestamp ZIP members. | Does not retrieve, redact, or inspect evidence payloads. |
| Manifest | Binds IDs, integrity hashes, lifecycle metadata, artifact metadata, and policy. | Does not establish truth, sufficiency, or auditor acceptance. |
| Verifier | Recomputes manifest hash and validates archive layout. | Does not certify compliance or verify original source data. |

The package pins [`cyrisk-core` v0.1.0](https://github.com/kingsokafor777-droid/cyrisk-core/releases/tag/v0.1.0)
commit `4d68f385ef382a6420466dff0196244a2c915f1f` for canonical JSON and payload-blind evidence
reference semantics.
