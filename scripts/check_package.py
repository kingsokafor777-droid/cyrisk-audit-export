"""Verify that the built wheel contains public typed source but no fixtures or tests."""

from __future__ import annotations

import zipfile
from pathlib import Path


def main() -> int:
    wheels = sorted(Path("dist").glob("cyrisk_audit_export-0.1.0-*.whl"))
    if len(wheels) != 1:
        raise SystemExit("expected exactly one cyrisk_audit_export v0.1.0 wheel")
    with zipfile.ZipFile(wheels[0]) as archive:
        names = set(archive.namelist())
    required = {
        "cyrisk_audit_export/__init__.py",
        "cyrisk_audit_export/models.py",
        "cyrisk_audit_export/package.py",
        "cyrisk_audit_export/py.typed",
    }
    missing = required - names
    if missing:
        raise SystemExit(f"wheel missing required content: {sorted(missing)}")
    forbidden = {
        name for name in names if name.startswith("fixtures/") or name.startswith("tests/")
    }
    if forbidden:
        raise SystemExit(f"wheel contains forbidden content: {sorted(forbidden)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
