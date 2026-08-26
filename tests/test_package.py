from __future__ import annotations

import json
import zipfile
from pathlib import Path

import pytest
from pydantic import ValidationError

from cyrisk_audit_export.cli import main
from cyrisk_audit_export.models import PackageRequest, VerificationRecord
from cyrisk_audit_export.package import (
    FIXED_TIMESTAMP,
    MEMBERS,
    PackageVerificationError,
    build_package,
    verify_package,
)

ROOT = Path(__file__).resolve().parents[1]
REQUEST_PATH = ROOT / "fixtures" / "synthetic_request.json"


def request() -> PackageRequest:
    return PackageRequest.model_validate_json(REQUEST_PATH.read_text(encoding="utf-8"))


def test_identical_metadata_produces_identical_bytes_and_verifies(tmp_path: Path) -> None:
    first = tmp_path / "first.zip"
    second = tmp_path / "second.zip"
    first_result = build_package(request(), first)
    second_result = build_package(request(), second)
    assert first.read_bytes() == second.read_bytes()
    assert first_result == second_result
    verification = verify_package(first)
    assert verification.archive_sha256 == first_result.archive_sha256
    assert verification.verified is True


def test_package_members_have_fixed_layout_timestamp_and_canonical_json(tmp_path: Path) -> None:
    package = tmp_path / "package.zip"
    build_package(request(), package)
    with zipfile.ZipFile(package) as archive:
        assert tuple(archive.namelist()) == MEMBERS
        assert all(info.date_time == FIXED_TIMESTAMP for info in archive.infolist())
        assert all(info.compress_type == zipfile.ZIP_STORED for info in archive.infolist())
        manifest = json.loads(archive.read("manifest.json"))
    assert manifest["evidence"][0]["evidence_id"] == "evidence_synthetic"
    assert "raw_evidence" not in manifest


@pytest.mark.parametrize(
    ("mutation", "expected"),
    [
        ("member", "archive_members_invalid"),
        ("timestamp", "archive_timestamp_invalid"),
        ("compression", "archive_compression_invalid"),
        ("noncanonical", "member_is_not_canonical_json"),
        ("invalidjson", "member_is_not_valid_utf8_json"),
    ],
)
def test_verifier_rejects_archive_layout_and_member_mutations(
    tmp_path: Path, mutation: str, expected: str
) -> None:
    source = tmp_path / "source.zip"
    target = tmp_path / "target.zip"
    build_package(request(), source)
    with zipfile.ZipFile(source) as archive:
        contents = {name: archive.read(name) for name in archive.namelist()}
    if mutation == "member":
        contents = {"other.json": contents["manifest.json"]}
    elif mutation == "noncanonical":
        contents["manifest.json"] = b'{ "schema_version" : "cyrisk.audit-export/v1" }'
    elif mutation == "invalidjson":
        contents["manifest.json"] = b"not-json"
    compression = zipfile.ZIP_DEFLATED if mutation == "compression" else zipfile.ZIP_STORED
    timestamp = (1981, 1, 1, 0, 0, 0) if mutation == "timestamp" else FIXED_TIMESTAMP
    with zipfile.ZipFile(target, "w", compression=compression) as archive:
        for name, data in contents.items():
            info = zipfile.ZipInfo(name, date_time=timestamp)
            info.compress_type = compression
            archive.writestr(info, data)
    with pytest.raises(PackageVerificationError, match=expected):
        verify_package(target)


def test_verifier_rejects_corrupted_manifest_and_verification_records(tmp_path: Path) -> None:
    source = tmp_path / "source.zip"
    target = tmp_path / "target.zip"
    build_package(request(), source)
    with zipfile.ZipFile(source) as archive:
        manifest = json.loads(archive.read("manifest.json"))
        verification = json.loads(archive.read("verification.json"))
    manifest["manifest_hash"] = "0" * 64
    with zipfile.ZipFile(target, "w") as archive:
        for name, content in (("manifest.json", manifest), ("verification.json", verification)):
            info = zipfile.ZipInfo(name, date_time=FIXED_TIMESTAMP)
            info.compress_type = zipfile.ZIP_STORED
            archive.writestr(info, json.dumps(content, sort_keys=True, separators=(",", ":")))
    with pytest.raises(PackageVerificationError, match="manifest_integrity_failure"):
        verify_package(target)


def test_verifier_rejects_nonzip_and_nonobject_json_members(tmp_path: Path) -> None:
    nonzip = tmp_path / "not-a-zip.bin"
    nonzip.write_bytes(b"not-a-zip")
    with pytest.raises(PackageVerificationError, match="archive_is_not_valid_zip"):
        verify_package(nonzip)
    source = tmp_path / "source.zip"
    target = tmp_path / "array-member.zip"
    build_package(request(), source)
    with zipfile.ZipFile(source) as archive:
        verification = archive.read("verification.json")
    with zipfile.ZipFile(target, "w") as archive:
        for name, content in (("manifest.json", b"[]"), ("verification.json", verification)):
            info = zipfile.ZipInfo(name, date_time=FIXED_TIMESTAMP)
            info.compress_type = zipfile.ZIP_STORED
            archive.writestr(info, content)
    with pytest.raises(PackageVerificationError, match="member_is_not_json_object"):
        verify_package(target)


@pytest.mark.parametrize("mutation", ["invalid_hash", "manifest_mismatch"])
def test_verifier_rejects_verification_record_tampering(tmp_path: Path, mutation: str) -> None:
    source = tmp_path / "source.zip"
    target = tmp_path / "target.zip"
    build_package(request(), source)
    with zipfile.ZipFile(source) as archive:
        manifest = archive.read("manifest.json")
        verification = json.loads(archive.read("verification.json"))
    if mutation == "invalid_hash":
        verification["verification_hash"] = "0" * 64
        expected = "verification_integrity_failure"
    else:
        unsealed = VerificationRecord.model_validate(
            {**verification, "manifest_hash": "0" * 64, "verification_hash": None}
        )
        verification = unsealed.seal().model_dump(mode="json")
        expected = "verification_manifest_mismatch"
    with zipfile.ZipFile(target, "w") as archive:
        for name, content in (("manifest.json", manifest), ("verification.json", verification)):
            info = zipfile.ZipInfo(name, date_time=FIXED_TIMESTAMP)
            info.compress_type = zipfile.ZIP_STORED
            if isinstance(content, bytes):
                archive.writestr(info, content)
            else:
                archive.writestr(info, json.dumps(content, sort_keys=True, separators=(",", ":")))
    with pytest.raises(PackageVerificationError, match=expected):
        verify_package(target)


def test_request_rejects_missing_policy_fields_and_raw_payload_field() -> None:
    payload = request().model_dump(mode="json")
    payload["redaction_policy"]["declared_redacted_fields"] = ["credential"]
    with pytest.raises(ValidationError, match="redaction policy must declare"):
        PackageRequest.model_validate(payload)
    payload = request().model_dump(mode="json")
    payload["evidence"][0]["raw_payload"] = "forbidden"
    with pytest.raises(ValidationError):
        PackageRequest.model_validate(payload)


def test_request_rejects_duplicate_ids() -> None:
    payload = request().model_dump(mode="json")
    payload["evidence"].append(payload["evidence"][0])
    with pytest.raises(ValidationError, match="evidence_id values must be unique"):
        PackageRequest.model_validate(payload)


def test_cli_build_and_verify_emit_local_json(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    output = tmp_path / "cli.zip"
    assert main(["build", str(REQUEST_PATH), str(output)]) == 0
    build_output = json.loads(capsys.readouterr().out)
    assert build_output["package_id"] == "pkg_synthetic"
    assert main(["verify", str(output)]) == 0
    verify_output = json.loads(capsys.readouterr().out)
    assert verify_output["verified"] is True
