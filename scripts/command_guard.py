#!/usr/bin/env python3
"""Validate and optionally run a tightly bounded read-only command plan."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Any


class PolicyError(ValueError):
    """Raised when a plan violates local execution policy."""


SHELL_META = re.compile(r"[;&|`$><\n\r]")
SERVICE_NAME = re.compile(r"^[A-Za-z0-9_.@-]+$")
READ_ONLY_PROGRAMS = {"df", "du", "journalctl", "systemctl"}


def canonical_plan(plan: dict[str, Any]) -> bytes:
    return json.dumps(plan, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def validate_common(plan: dict[str, Any]) -> list[str]:
    argv = plan.get("argv")
    if not isinstance(plan.get("purpose"), str) or not plan["purpose"].strip():
        raise PolicyError("purpose must be a non-empty string")
    if not isinstance(argv, list) or not argv or not all(isinstance(x, str) and x for x in argv):
        raise PolicyError("argv must be a non-empty list of strings")
    if any(SHELL_META.search(arg) for arg in argv):
        raise PolicyError("shell metacharacters are not allowed")
    if "/" in argv[0] or argv[0] not in READ_ONLY_PROGRAMS:
        raise PolicyError("program is not on the read-only allowlist")
    timeout = plan.get("timeout_seconds", 10)
    if not isinstance(timeout, int) or not 1 <= timeout <= 30:
        raise PolicyError("timeout_seconds must be an integer from 1 to 30")
    return argv


def validate_df(argv: list[str]) -> None:
    allowed_flags = {"-h", "-P", "-T"}
    for arg in argv[1:]:
        if arg.startswith("-") and arg not in allowed_flags:
            raise PolicyError(f"df flag is not allowed: {arg}")


def validate_du(argv: list[str]) -> None:
    allowed_flags = {"-h", "-s", "-x", "--max-depth=1"}
    roots = [Path.cwd().resolve(), Path("/var/log"), Path("/tmp/linux-ai-lab")]
    for arg in argv[1:]:
        if arg.startswith("-"):
            if arg not in allowed_flags:
                raise PolicyError(f"du flag is not allowed: {arg}")
            continue
        resolved = Path(arg).resolve()
        if not any(resolved == root or root in resolved.parents for root in roots):
            raise PolicyError(f"du path is outside approved roots: {arg}")


def validate_systemctl(argv: list[str]) -> None:
    if len(argv) not in {2, 3} or argv[1] not in {"status", "show", "is-active"}:
        raise PolicyError("systemctl is limited to status, show and is-active")
    if len(argv) == 3 and not SERVICE_NAME.fullmatch(argv[2]):
        raise PolicyError("invalid systemd unit name")


def validate_journalctl(argv: list[str]) -> None:
    index = 1
    while index < len(argv):
        arg = argv[index]
        if arg in {"-f", "--follow"}:
            raise PolicyError("unbounded log following is not allowed")
        if arg in {"--no-pager", "--output=json", "--output=short-iso"}:
            index += 1
            continue
        if arg in {"-n", "-u"} and index + 1 < len(argv):
            value = argv[index + 1]
            if arg == "-n" and (not value.isdigit() or not 1 <= int(value) <= 500):
                raise PolicyError("journalctl line limit must be from 1 to 500")
            if arg == "-u" and not SERVICE_NAME.fullmatch(value):
                raise PolicyError("invalid systemd unit name")
            index += 2
            continue
        raise PolicyError(f"journalctl argument is not allowed: {arg}")


def validate_plan(plan: dict[str, Any]) -> list[str]:
    argv = validate_common(plan)
    validators = {
        "df": validate_df,
        "du": validate_du,
        "journalctl": validate_journalctl,
        "systemctl": validate_systemctl,
    }
    validators[argv[0]](argv)
    return argv


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--execute-read-only", action="store_true")
    args = parser.parse_args()

    try:
        plan = json.loads(args.plan.read_text(encoding="utf-8"))
        if not isinstance(plan, dict):
            raise PolicyError("plan must be a JSON object")
        argv = validate_plan(plan)
    except (OSError, json.JSONDecodeError, PolicyError) as exc:
        print(f"DECISION: DENY\nREASON: {exc}", file=sys.stderr)
        return 1

    plan_id = hashlib.sha256(canonical_plan(plan)).hexdigest()[:16]
    print(f"PLAN_ID: {plan_id}")
    print("DECISION: ALLOW_READ_ONLY")
    print(f"COMMAND: {argv!r}")

    if not args.execute_read_only:
        print("MODE: DRY_RUN")
        print("No command was executed.")
        return 0

    started = time.monotonic()
    try:
        result = subprocess.run(
            argv,
            shell=False,
            capture_output=True,
            text=True,
            timeout=plan.get("timeout_seconds", 10),
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        print(f"EXECUTION_ERROR: {exc}", file=sys.stderr)
        return 1
    elapsed_ms = int((time.monotonic() - started) * 1000)
    print("MODE: EXECUTE_READ_ONLY")
    print(f"EXIT_CODE: {result.returncode}")
    print(f"ELAPSED_MS: {elapsed_ms}")
    print("STDOUT:")
    print(result.stdout[:8_000].rstrip())
    if result.stderr:
        print("STDERR:", file=sys.stderr)
        print(result.stderr[:2_000].rstrip(), file=sys.stderr)
    return 0 if result.returncode == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())

