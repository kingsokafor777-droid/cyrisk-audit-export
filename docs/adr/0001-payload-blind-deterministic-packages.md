# ADR 0001: Build payload-blind deterministic packages

**Status:** Accepted

The first release packages only validated metadata and canonical hashes. Raw evidence, locators,
credentials, and source-system clients are deliberately excluded. This gives deployers a reproducible
preparation artifact while keeping evidence handling, authorization, redaction execution, and audit
judgment outside this source release.
