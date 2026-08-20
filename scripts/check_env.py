#!/usr/bin/env python3
"""Validate the Linux AI Lab without revealing secret values."""

from __future__ import annotations

import os
import sys
from pathlib import Path


REQUIRED_ENV = (
    "CHRONO_AI_BASE_URL",
    "CHRONO_AI_API_KEY",
    "CHRONO_AI_MODEL",
)

# check_env.py 位于 scripts/ 目录中，向上一级是项目根目录
PROJECT_ROOT = Path(__file__).resolve().parent.parent
FIXTURE_PATH = PROJECT_ROOT / "fixtures" / "app.log"


def main() -> int:
    failed = False

    print(
        f"[OK] Python: "
        f"{sys.version_info.major}."
        f"{sys.version_info.minor}."
        f"{sys.version_info.micro}"
    )

    for name in REQUIRED_ENV:
        if os.getenv(name):
            suffix = " (value hidden)" if name.endswith("API_KEY") else ""
            print(f"[OK] {name}: configured{suffix}")
        else:
            print(f"[FAIL] {name}: not configured")
            failed = True

    if FIXTURE_PATH.is_file():
        relative_path = FIXTURE_PATH.relative_to(PROJECT_ROOT)
        print(f"[OK] Fixture: {relative_path}")
    else:
        print("[FAIL] Fixture: fixtures/app.log is missing")
        failed = True

    if failed:
        print("Lab is incomplete. No production action was executed.")
        return 1

    print("Lab is ready. No production action was executed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
