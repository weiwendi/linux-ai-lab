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


def main() -> int:
    failed = False
    print(f"[OK] Python: {sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}")

    for name in REQUIRED_ENV:
        if os.getenv(name):
            suffix = " (value hidden)" if name.endswith("API_KEY") else ""
            print(f"[OK] {name}: configured{suffix}")
        else:
            print(f"[FAIL] {name}: not configured")
            failed = True

    fixture = Path(__file__).resolve().parent / "fixtures" / "app.log"
    if fixture.is_file():
        print(f"[OK] Fixture: {fixture.relative_to(Path(__file__).resolve().parent)}")
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

