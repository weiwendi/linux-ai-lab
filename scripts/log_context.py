#!/usr/bin/env python3
"""Build a bounded, redacted evidence pack from journald JSON records."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
SECRET = re.compile(r"(?i)\b(api[_-]?key|token|password|authorization)=([^\s]+)")


def pseudonym(kind: str, value: str, salt: str) -> str:
    digest = hashlib.sha256(f"{salt}:{kind}:{value}".encode("utf-8")).hexdigest()[:8]
    return f"[{kind}-{digest}]"


def redact(text: str, salt: str) -> tuple[str, int]:
    count = 0

    def replace_ip(match: re.Match[str]) -> str:
        nonlocal count
        count += 1
        return pseudonym("IP", match.group(0), salt)

    def replace_email(match: re.Match[str]) -> str:
        nonlocal count
        count += 1
        return pseudonym("EMAIL", match.group(0), salt)

    def replace_secret(match: re.Match[str]) -> str:
        nonlocal count
        count += 1
        return f"{match.group(1)}=[REDACTED]"

    text = IPV4.sub(replace_ip, text)
    text = EMAIL.sub(replace_email, text)
    text = SECRET.sub(replace_secret, text)
    return text, count


def iso_timestamp(value: Any) -> str:
    try:
        micros = int(value)
        return datetime.fromtimestamp(micros / 1_000_000, tz=timezone.utc).isoformat().replace("+00:00", "Z")
    except (TypeError, ValueError, OSError):
        return "unknown"


def iter_json_lines(lines: Iterable[str]) -> Iterable[dict[str, Any]]:
    for number, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"invalid JSON on input line {number}: {exc.msg}") from exc
        if isinstance(value, dict):
            yield value


def live_journal(unit: str, since: str, lines: int) -> list[str]:
    if not re.fullmatch(r"[A-Za-z0-9_.@-]+", unit):
        raise ValueError("invalid systemd unit name")
    if not 1 <= lines <= 500:
        raise ValueError("--lines must be from 1 to 500")
    cmd = [
        "journalctl",
        "-u",
        unit,
        "--since",
        since,
        "-n",
        str(lines),
        "--no-pager",
        "--output=json",
    ]
    result = subprocess.run(cmd, shell=False, capture_output=True, text=True, timeout=15, check=False)
    if result.returncode != 0:
        raise RuntimeError(f"journalctl failed: {result.stderr.strip()[:500]}")
    return result.stdout.splitlines()


def main() -> int:
    parser = argparse.ArgumentParser()
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--input", type=Path)
    source.add_argument("--unit")
    parser.add_argument("--since", default="10 minutes ago")
    parser.add_argument("--lines", type=int, default=300)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    try:
        raw_lines = (
            args.input.read_text(encoding="utf-8").splitlines()
            if args.input
            else live_journal(args.unit, args.since, args.lines)
        )
        salt = os.getenv("REDACTION_SALT", "linux-ai-lab-only")
        records = []
        redaction_count = 0
        for number, item in enumerate(iter_json_lines(raw_lines), start=1):
            message, count = redact(str(item.get("MESSAGE", ""))[:2_000], salt)
            redaction_count += count
            try:
                priority = int(item.get("PRIORITY", 6))
            except (TypeError, ValueError):
                priority = 6
            records.append(
                {
                    "evidence_id": f"E{number:03d}",
                    "timestamp": iso_timestamp(item.get("__REALTIME_TIMESTAMP")),
                    "priority": priority,
                    "unit": str(item.get("_SYSTEMD_UNIT", args.unit or "unknown")),
                    "message": message,
                    "signal": priority <= 4,
                }
            )
        pack = {
            "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "source": str(args.input) if args.input else f"journald:{args.unit}",
            "handling": {
                "field_allowlist": ["timestamp", "priority", "unit", "message"],
                "pseudonymized": True,
                "max_message_chars": 2000,
            },
            "records": records[:500],
        }
        args.output.write_text(json.dumps(pack, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as exc:
        print(f"{type(exc).__name__}: {exc}", file=sys.stderr)
        return 1

    print(f"records_read={len(raw_lines)} records_written={len(pack['records'])} redactions={redaction_count}")
    print(f"evidence_pack={args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

