"""Deterministic fixed-layout ZIP construction and offline verification."""

from __future__ import annotations

import hashlib
import json
import zipfile
from pathlib import Path
from typing import Literal, cast

from cyrisk_core.canonical import canonical_json

from .models import (
    PackageBuildResult,
    PackageManifest,
    PackageRequest,
    VerificationRecord,
    VerificationResult,
)

MEMBERS: tuple[Literal["manifest.json", "verification.json"], ...] = (
    "manifest.json",
    "verification.json",
)
FIXED_TIMESTAMP = (1980, 1, 1, 0, 0, 0)
FILE_MODE = 0o100644 << 16


class PackageVerificationError(ValueError):
    """A deterministic package layout, canonicality, or integrity failure."""


def _archive_hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical_bytes(value: PackageManifest | VerificationRecord) -> bytes:
    return canonical_json(value).encode("utf-8")


def _member_info(name: str) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, date_time=FIXED_TIMESTAMP)
    info.compress_type = zipfile.ZIP_STORED
    info.external_attr = FILE_MODE
    info.create_system = 3
    return info


def _manifest_from_request(request: PackageRequest) -> PackageManifest:
    return PackageManifest(
        package_id=request.package_id,
        as_of=request.as_of,
        evidence=tuple(sorted(request.evidence, key=lambda item: item.evidence_id)),
        artifacts=tuple(sorted(request.artifacts, key=lambda item: item.artifact_id)),
        redaction_policy=request.redaction_policy,
        limitation=request.limitation,
    ).seal()


def build_package(request: PackageRequest, output_path: Path) -> PackageBuildResult:
    """Write a deterministic metadata-only ZIP package to the supplied local path."""

    manifest = _manifest_from_request(request)
    verification = VerificationRecord(
        package_id=request.package_id,
        manifest_hash=manifest.manifest_hash or "",
        members=MEMBERS,
    ).seal()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(
        output_path, "w", compression=zipfile.ZIP_STORED, strict_timestamps=True
    ) as archive:
        archive.writestr(_member_info("manifest.json"), _canonical_bytes(manifest))
        archive.writestr(_member_info("verification.json"), _canonical_bytes(verification))
    archive_data = output_path.read_bytes()
    return PackageBuildResult(
        package_id=request.package_id,
        manifest_hash=manifest.manifest_hash or "",
        archive_sha256=_archive_hash(archive_data),
        member_count=len(MEMBERS),
    )


def _read_canonical_member(archive: zipfile.ZipFile, name: str) -> dict[str, object]:
    encoded = archive.read(name)
    try:
        decoded = encoded.decode("utf-8")
        value = json.loads(decoded)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise PackageVerificationError("member_is_not_valid_utf8_json") from error
    canonical = canonical_json(value)
    if decoded != canonical:
        raise PackageVerificationError("member_is_not_canonical_json")
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise PackageVerificationError("member_is_not_json_object")
    return cast(dict[str, object], value)


def verify_package(package_path: Path) -> VerificationResult:
    """Verify only archive structure and declared package metadata integrity offline."""

    try:
        with zipfile.ZipFile(package_path) as archive:
            infos = archive.infolist()
            if tuple(info.filename for info in infos) != MEMBERS:
                raise PackageVerificationError("archive_members_invalid")
            if any(info.date_time != FIXED_TIMESTAMP for info in infos):
                raise PackageVerificationError("archive_timestamp_invalid")
            if any(info.compress_type != zipfile.ZIP_STORED for info in infos):
                raise PackageVerificationError("archive_compression_invalid")
            manifest = PackageManifest.model_validate(
                _read_canonical_member(archive, "manifest.json")
            )
            verification = VerificationRecord.model_validate(
                _read_canonical_member(archive, "verification.json")
            )
    except zipfile.BadZipFile as error:
        raise PackageVerificationError("archive_is_not_valid_zip") from error
    if not manifest.verify_integrity():
        raise PackageVerificationError("manifest_integrity_failure")
    if not verification.verify_integrity():
        raise PackageVerificationError("verification_integrity_failure")
    if (
        verification.package_id != manifest.package_id
        or verification.manifest_hash != manifest.manifest_hash
    ):
        raise PackageVerificationError("verification_manifest_mismatch")
    return VerificationResult(
        package_id=manifest.package_id,
        manifest_hash=manifest.manifest_hash or "",
        archive_sha256=_archive_hash(package_path.read_bytes()),
    )
