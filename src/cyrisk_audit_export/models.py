"""Strict metadata-only contracts for deterministic audit-preparation packages."""

from __future__ import annotations

from typing import Final, Literal

from cyrisk_core.canonical import content_hash
from cyrisk_core.models import SourceClass
from pydantic import BaseModel, ConfigDict, Field, field_validator

SCHEMA_VERSION: Final[Literal["cyrisk.audit-export/v1"]] = "cyrisk.audit-export/v1"
HASH_PATTERN = r"^[a-f0-9]{64}$"
ID_PATTERN = r"^[a-z][a-z0-9_-]{2,63}$"
TIMESTAMP_PATTERN = r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$"
DATE_PATTERN = r"^\d{4}-\d{2}-\d{2}$"
REQUIRED_REDACTION_FIELDS = frozenset({"credential", "payload_locator", "raw_evidence"})


class StrictModel(BaseModel):
    """Fail closed on unknown fields so payloads and locators cannot enter a package."""

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)


class EvidenceMetadata(StrictModel):
    """Payload-blind reference metadata; an integrity hash does not establish source truth."""

    evidence_id: str = Field(pattern=ID_PATTERN)
    source_class: SourceClass
    integrity_hash: str = Field(pattern=HASH_PATTERN)
    description: str = Field(min_length=1, max_length=240)
    expires_on: str | None = Field(default=None, pattern=DATE_PATTERN)


class ArtifactMetadata(StrictModel):
    """Hash-only reference to a supplied generated artifact; content is not exported."""

    artifact_id: str = Field(pattern=ID_PATTERN)
    artifact_kind: str = Field(pattern=r"^[a-z][a-z0-9_]{2,63}$")
    integrity_hash: str = Field(pattern=HASH_PATTERN)
    description: str = Field(min_length=1, max_length=240)


class RedactionPolicy(StrictModel):
    """A declared field policy; execution remains the deployer's responsibility."""

    policy_id: str = Field(pattern=ID_PATTERN)
    version: str = Field(pattern=r"^\d+\.\d+\.\d+$")
    declared_redacted_fields: tuple[str, ...] = Field(min_length=1)
    rationale: str = Field(min_length=1, max_length=500)

    @field_validator("declared_redacted_fields")
    @classmethod
    def require_mandatory_fields(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)):
            raise ValueError("declared_redacted_fields must be unique")
        missing = REQUIRED_REDACTION_FIELDS - set(value)
        if missing:
            raise ValueError(f"redaction policy must declare fields: {sorted(missing)}")
        return tuple(sorted(value))


class PackageRequest(StrictModel):
    """All input is supplied metadata. The package builder performs no retrieval or redaction."""

    schema_version: Literal["cyrisk.audit-export/v1"] = SCHEMA_VERSION
    package_id: str = Field(pattern=ID_PATTERN)
    as_of: str = Field(pattern=TIMESTAMP_PATTERN)
    evidence: tuple[EvidenceMetadata, ...] = Field(min_length=1)
    artifacts: tuple[ArtifactMetadata, ...] = Field(min_length=1)
    redaction_policy: RedactionPolicy
    limitation: str = Field(min_length=1, max_length=500)

    @field_validator("evidence", "artifacts")
    @classmethod
    def require_unique_ids(cls, value: tuple[object, ...]) -> tuple[object, ...]:
        attribute = (
            "evidence_id" if value and isinstance(value[0], EvidenceMetadata) else "artifact_id"
        )
        identifiers = [str(getattr(item, attribute)) for item in value]
        if len(identifiers) != len(set(identifiers)):
            raise ValueError(f"{attribute} values must be unique")
        return value


class PackageManifest(StrictModel):
    """Canonical archive inventory and hash; source-data truth remains explicitly out of scope."""

    schema_version: Literal["cyrisk.audit-export/v1"] = SCHEMA_VERSION
    package_id: str = Field(pattern=ID_PATTERN)
    as_of: str = Field(pattern=TIMESTAMP_PATTERN)
    evidence: tuple[EvidenceMetadata, ...]
    artifacts: tuple[ArtifactMetadata, ...]
    redaction_policy: RedactionPolicy
    limitation: str = Field(min_length=1, max_length=500)
    manifest_hash: str | None = Field(default=None, pattern=HASH_PATTERN)

    def computed_hash(self) -> str:
        return content_hash(self.model_dump(mode="json", exclude={"manifest_hash"}))

    def seal(self) -> PackageManifest:
        return self.model_copy(update={"manifest_hash": self.computed_hash()})

    def verify_integrity(self) -> bool:
        return self.manifest_hash is not None and self.manifest_hash == self.computed_hash()


class VerificationRecord(StrictModel):
    """Package-level verification result, not a statement about original source evidence."""

    schema_version: Literal["cyrisk.audit-export/v1"] = SCHEMA_VERSION
    package_id: str = Field(pattern=ID_PATTERN)
    manifest_hash: str = Field(pattern=HASH_PATTERN)
    members: tuple[Literal["manifest.json", "verification.json"], ...]
    verification_hash: str | None = Field(default=None, pattern=HASH_PATTERN)
    limitation: str = (
        "Verification checks the local package layout and declared metadata integrity only; "
        "it does not establish source truth, sufficiency, auditor acceptance, or "
        "compliance certification."
    )

    def computed_hash(self) -> str:
        return content_hash(self.model_dump(mode="json", exclude={"verification_hash"}))

    def seal(self) -> VerificationRecord:
        return self.model_copy(update={"verification_hash": self.computed_hash()})

    def verify_integrity(self) -> bool:
        return self.verification_hash is not None and self.verification_hash == self.computed_hash()


class PackageBuildResult(StrictModel):
    """Reference to generated archive bytes with a deterministic package-level digest."""

    package_id: str = Field(pattern=ID_PATTERN)
    manifest_hash: str = Field(pattern=HASH_PATTERN)
    archive_sha256: str = Field(pattern=HASH_PATTERN)
    member_count: int = Field(ge=2, le=2)


class VerificationResult(StrictModel):
    """Offline verifier output with no claim about the packaged source evidence."""

    package_id: str = Field(pattern=ID_PATTERN)
    manifest_hash: str = Field(pattern=HASH_PATTERN)
    archive_sha256: str = Field(pattern=HASH_PATTERN)
    verified: Literal[True] = True
