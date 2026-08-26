"""Deliberately generate the expected result for the sealed synthetic request fixture."""

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
        build = build_package(request, package_path)
        verification = verify_package(package_path)
    expected = {
        "build": build.model_dump(mode="json"),
        "verification": verification.model_dump(mode="json"),
    }
    EXPECTED_PATH.write_text(
        json.dumps(expected, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
