"""Local JSON build and verify commands for metadata-only package preparation."""

from __future__ import annotations

import argparse
from collections.abc import Sequence
from pathlib import Path

from .models import PackageBuildResult, PackageRequest, VerificationResult
from .package import build_package, verify_package


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build or verify a payload-blind Cyrisk package.")
    commands = parser.add_subparsers(dest="command", required=True)
    build = commands.add_parser("build")
    build.add_argument("input", type=Path, help="Local PackageRequest JSON path")
    build.add_argument("output", type=Path, help="Local deterministic ZIP output path")
    verify = commands.add_parser("verify")
    verify.add_argument("package", type=Path, help="Local ZIP path")
    args = parser.parse_args(argv)
    result: PackageBuildResult | VerificationResult
    if args.command == "build":
        request = PackageRequest.model_validate_json(args.input.read_text(encoding="utf-8"))
        result = build_package(request, args.output)
    else:
        result = verify_package(args.package)
    print(result.model_dump_json())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
