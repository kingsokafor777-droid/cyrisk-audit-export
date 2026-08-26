"""Verify the sealed synthetic fixture produces its committed deterministic result."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from cyrisk_audit_export.models import PackageRequest
from cyrisk_audit_export.package import build_package, verify_package

ROOT = Path(__file__).resolve().parents[1]
REQUEST_PATH = ROOT / "fixtures" / "synthetic_request.json"
EXPECTED_PATH = ROOT / "fixtures" / "expected_result.json"


def main() -> int:
    request = PackageRequest.model_validate_json(REQUEST_PATH.read_text(encoding="utf-8"))
    with tempfile.TemporaryDirectory() as directory:
        package_path = Path(directory) / "synthetic.zip"
        actual = {
            "build": build_package(request, package_path).model_dump(mode="json"),
            "verification": verify_package(package_path).model_dump(mode="json"),
        }
    expected = json.loads(EXPECTED_PATH.read_text(encoding="utf-8"))
    if actual != expected:
        raise SystemExit("sealed fixture result differs; review before deliberately regenerating")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
